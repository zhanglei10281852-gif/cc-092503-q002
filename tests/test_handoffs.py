from __future__ import annotations

import concurrent.futures

from app.core.security import Principal
from app.database import close_connection, get_connection
from app.samples.handoff_service import HandoffService


def _make_location(client, admin, code="HN-LOC-01"):
    response = client.post(
        "/api/samples/locations",
        headers=admin["headers"],
        json={"code": code, "building": "样品楼", "room": "常温库",
              "cabinet": "一号柜", "shelf": "一层", "sensitivity": "normal",
              "capacity_units": 100},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _make_batch(client, admin, code="HN-BATCH-01", expected=2):
    response = client.post(
        "/api/samples/batches",
        headers=admin["headers"],
        json={"batch_code": code, "project_code": "HN", "expected_count": expected},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _issue(client, admin, batch_id, party="野外一队", ttl=120):
    response = client.post(
        "/api/handoffs/credentials",
        headers=admin["headers"],
        json={"batch_id": batch_id, "handoff_party": party, "ttl_minutes": ttl},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _receive_payload(qr, key, party="野外一队", *, accepted_code="HN-S-1", location_id=None,
                     expected=2):
    return {
        "qr_content": qr,
        "idempotency_key": key,
        "handoff_party": party,
        "expected_count": expected,
        "items": [
            {"line_no": 1, "sample_code": accepted_code, "accepted": True,
             "sample_type": "土壤", "quantity": 50, "unit": "g",
             "location_id": location_id},
            {"line_no": 2, "sample_code": f"{accepted_code}-R", "accepted": False,
             "reject_reason": "容器破损，样品泄漏"},
        ],
        "note": "整箱交接",
    }


def _setup_issued(client, admin, code="HN-BATCH-01", party="野外一队", ttl=120, expected=2):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin, code=code, expected=expected)
    issued = _issue(client, admin, batch["id"], party=party, ttl=ttl)
    return location, batch, issued


def test_issue_returns_qr_once_and_queries_do_not_leak(client, admin):
    location, batch, issued = _setup_issued(client, admin)
    assert issued["version"] == 1
    assert issued["status"] == "active"
    qr = issued["qr_content"]
    assert qr.startswith("HND1.")

    # 列表 / 详情 / 批次轨迹都不得回传可重放二维码或密钥哈希
    listing = client.get(f"/api/handoffs/batches/{batch['id']}/credentials", headers=admin["headers"])
    assert listing.status_code == 200
    for item in listing.json():
        assert "qr_content" not in item
        assert "key_digest" not in item

    detail = client.get(f"/api/handoffs/credentials/{issued['id']}", headers=admin["headers"])
    assert detail.status_code == 200
    body = detail.json()
    assert "qr_content" not in body and "key_digest" not in body
    assert any(e["event_type"] == "credential.issued" for e in body["trail"])

    trail = client.get(f"/api/handoffs/batches/{batch['id']}/trail", headers=admin["headers"])
    assert trail.status_code == 200
    text = trail.text
    assert qr not in text and "key_digest" not in text


def test_receive_is_idempotent_and_atomic(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin)
    issued = _issue(client, admin, batch["id"])
    payload = _receive_payload(issued["qr_content"], "recv-001", location_id=location["id"])

    first = client.post("/api/handoffs/receive", headers=admin["headers"], json=payload)
    assert first.status_code == 201, first.text
    first_body = first.json()
    assert first_body["replayed"] is False
    receipt = first_body["receipt"]
    assert receipt["accepted_count"] == 1
    assert receipt["rejected_count"] == 1
    assert len(receipt["items"]) == 2
    rejected_item = next(i for i in receipt["items"] if not i["accepted"])
    accepted_item = next(i for i in receipt["items"] if i["accepted"])
    assert rejected_item["reject_reason"] == "容器破损，样品泄漏"
    assert accepted_item["location_id"] == location["id"]
    assert accepted_item["sample_id"] is not None

    # 批次计数原子落库：1 接收 + 1 拒收
    refreshed_batch = client.get(
        "/api/sample-operations/batches/{}/reconciliation".format(batch["id"]),
        headers=admin["headers"],
    ).json()["batch"]
    assert refreshed_batch["accepted_count"] == 1
    assert refreshed_batch["rejected_count"] == 1

    # 重复扫码：同一幂等键返回同一回执，不重复入库
    second = client.post("/api/handoffs/receive", headers=admin["headers"], json=payload)
    assert second.status_code == 201
    second_body = second.json()
    assert second_body["replayed"] is True
    assert second_body["receipt"]["id"] == receipt["id"]

    samples = client.get(f"/api/samples?batch_id={batch['id']}", headers=admin["headers"]).json()
    assert len(samples) == 1


def test_rotated_old_version_is_rejected_and_new_version_works(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin)
    issued = _issue(client, admin, batch["id"])
    old_qr = issued["qr_content"]

    rotated = client.post(
        f"/api/handoffs/batches/{batch['id']}/credentials/rotate",
        headers=admin["headers"], json={"ttl_minutes": 60},
    )
    assert rotated.status_code == 201, rotated.text
    new_qr = rotated.json()["qr_content"]
    assert new_qr != old_qr
    assert rotated.json()["version"] == 2

    # 旧版本码可区分地拒绝
    stale = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(old_qr, "recv-old", location_id=location["id"]),
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "credential_version_stale"

    # 新版本码正常接收
    ok = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(new_qr, "recv-new", location_id=location["id"]),
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["replayed"] is False


def test_expired_credential_is_rejected(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin, code="HN-BATCH-EXP")
    issued = _issue(client, admin, batch["id"], ttl=1)
    # 将有效期改到过去，模拟凭证到期
    connection = get_connection()
    connection.execute(
        "UPDATE handoff_credentials SET expires_at='2020-01-01T00:00:00+00:00' WHERE id=?",
        (issued["id"],),
    )
    response = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], "recv-exp", location_id=location["id"]),
    )
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "credential_expired"


def test_closed_batch_is_rejected(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin, code="HN-BATCH-CLOSED")
    issued = _issue(client, admin, batch["id"])
    closed = client.post(f"/api/samples/batches/{batch['id']}/close", headers=admin["headers"])
    assert closed.status_code == 200
    response = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], "recv-closed", location_id=location["id"]),
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "batch_closed"


def test_revoke_unused_blocks_scan_and_used_cannot_revoke(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin, code="HN-BATCH-REV")
    issued = _issue(client, admin, batch["id"])

    revoked = client.post(
        f"/api/handoffs/credentials/{issued['id']}/revoke",
        headers=admin["headers"], json={"reason": "野外队临时取消交接"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    response = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], "recv-rev", location_id=location["id"]),
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "credential_revoked"

    # 已用于交接的凭证不能撤销
    batch2 = _make_batch(client, admin, code="HN-BATCH-USED")
    issued2 = _issue(client, admin, batch2["id"])
    ok = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(issued2["qr_content"], "recv-used", location_id=location["id"],
                              accepted_code="HN-S-USED"),
    )
    assert ok.status_code == 201
    revoke_used = client.post(
        f"/api/handoffs/credentials/{issued2['id']}/revoke", headers=admin["headers"], json={}
    )
    assert revoke_used.status_code == 409


def test_handoff_party_mismatch_is_distinguished(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin, code="HN-BATCH-PARTY")
    issued = _issue(client, admin, batch["id"], party="野外一队")
    response = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], "recv-party", party="野外二队",
                              location_id=location["id"]),
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "handoff_party_mismatch"


def test_unknown_or_tampered_qr_is_rejected_without_disclosure(client, admin):
    location = _make_location(client, admin, code="HN-LOC-UNK")
    batch = _make_batch(client, admin, code="HN-BATCH-UNK")
    issued = _issue(client, admin, batch["id"])
    # 篡改密钥
    tampered = issued["qr_content"][:-4] + "aaaa"
    response = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(tampered, "recv-tamper", location_id=location["id"]),
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "credential_unknown"
    # 不存在的凭证 id
    response2 = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload("HND1.999999.1.abcdefgh", "recv-missing",
                              location_id=location["id"]),
    )
    assert response2.status_code == 404
    assert response2.json()["error"]["code"] == "credential_unknown"


def test_admin_can_view_full_trail_including_denials(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin, code="HN-BATCH-TRAIL")
    issued = _issue(client, admin, batch["id"])
    # 一次过期拒绝
    connection = get_connection()
    connection.execute(
        "UPDATE handoff_credentials SET expires_at='2020-01-01T00:00:00+00:00' WHERE id=?",
        (issued["id"],),
    )
    denied = client.post(
        "/api/handoffs/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], "recv-deny", location_id=location["id"]),
    )
    assert denied.status_code == 410

    trail = client.get(f"/api/handoffs/batches/{batch['id']}/trail", headers=admin["headers"]).json()
    event_types = [e["event_type"] for e in trail["events"]]
    assert "credential.issued" in event_types
    assert "receive.expired" in event_types
    denied_event = next(e for e in trail["events"] if e["event_type"] == "receive.expired")
    assert denied_event["result"] == "denied"
    assert denied_event["detail"]["expires_at"].startswith("2020")


def test_concurrent_handoff_succeeds_once(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin, code="HN-BATCH-CONC")
    issued = _issue(client, admin, batch["id"])
    qr = issued["qr_content"]
    location_id = location["id"]

    # 每个工作线程使用独立的线程局部数据库连接，真正触发 BEGIN IMMEDIATE 锁竞争
    def worker(key):
        principal = Principal(
            user_id=1, username="admin", display_name="主管", department_id=None,
            permissions=frozenset({"*"}), session_id=1,
        )
        connection = get_connection()  # 在线程内建立独立连接
        service = HandoffService(connection)
        payload = _receive_payload(qr, key, location_id=location_id, accepted_code=f"HN-C-{key}")
        try:
            result = service.receive(principal, payload)
            return ("ok", result["replayed"])
        except Exception as exc:  # noqa: BLE001 - 并发下期望其中一方被拒
            return (getattr(exc, "code", type(exc).__name__), None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker, "c1"), pool.submit(worker, "c2")]
        outcomes = [f.result() for f in futures]

    codes = sorted(code for code, _ in outcomes)
    assert codes == ["credential_already_used", "ok"], outcomes

    # 只有一张成功回执、一个入库样品
    connection = get_connection()
    receipt_count = connection.execute(
        "SELECT COUNT(*) FROM handoff_receipts WHERE batch_id=?", (batch["id"],)
    ).fetchone()[0]
    sample_count = connection.execute(
        "SELECT COUNT(*) FROM samples WHERE batch_id=?", (batch["id"],)
    ).fetchone()[0]
    assert receipt_count == 1
    assert sample_count == 1


def test_results_persist_across_service_restart(client, admin):
    location = _make_location(client, admin)
    batch = _make_batch(client, admin, code="HN-BATCH-RESTART")
    issued = _issue(client, admin, batch["id"])
    payload = _receive_payload(issued["qr_content"], "recv-restart", location_id=location["id"],
                               accepted_code="HN-S-RESTART")
    first = client.post("/api/handoffs/receive", headers=admin["headers"], json=payload)
    assert first.status_code == 201
    receipt_id = first.json()["receipt"]["id"]

    # 模拟服务重启：关闭连接并重建客户端
    close_connection()
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as restarted:
        login = restarted.post(
            "/api/auth/login",
            json={"username": "admin", "password": "Admin!23456", "client_label": "tests"},
        )
        headers = {"Authorization": f"Bearer {login.json()['token']}"}

        # 重启后同幂等键重放仍返回同一回执
        replay = restarted.post("/api/handoffs/receive", headers=headers, json=payload)
        assert replay.status_code == 201
        assert replay.json()["replayed"] is True
        assert replay.json()["receipt"]["id"] == receipt_id

        # 重启后用新幂等键扫已用凭证，仍被可区分拒绝
        payload["idempotency_key"] = "recv-restart-again"
        again = restarted.post("/api/handoffs/receive", headers=headers, json=payload)
        assert again.status_code == 409
        assert again.json()["error"]["code"] == "credential_already_used"
    close_connection()


def _login_as(client, username, password):
    login = client.post(
        "/api/auth/login",
        json={"username": username, "password": password, "client_label": "tests"},
    )
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['token']}"}


def test_researcher_cannot_issue_receive_or_read_trail(client, admin):
    location = _make_location(client, admin, code="HN-LOC-PERM")
    batch = _make_batch(client, admin, code="HN-BATCH-PERM")
    # 创建一个只有 researcher 角色的普通用户
    created = client.post(
        "/api/users", headers=admin["headers"],
        json={"username": "field_user", "password": "Field!23456",
              "display_name": "野外队员", "role_codes": ["researcher"]},
    )
    assert created.status_code == 201, created.text
    user_headers = _login_as(client, "field_user", "Field!23456")

    # 无 handoffs 权限：颁发、扫码、轨迹全部 403
    issue = client.post(
        "/api/handoffs/credentials", headers=user_headers,
        json={"batch_id": batch["id"], "handoff_party": "野外一队"},
    )
    assert issue.status_code == 403

    trail = client.get(f"/api/handoffs/batches/{batch['id']}/trail", headers=user_headers)
    assert trail.status_code == 403

    listing = client.get(f"/api/handoffs/batches/{batch['id']}/credentials", headers=user_headers)
    assert listing.status_code == 403

    # 匿名请求被认证层拒绝，不进入业务逻辑
    anon = client.post(
        "/api/handoffs/receive",
        json=_receive_payload("HND1.1.1.x", "recv-anon", location_id=location["id"]),
    )
    assert anon.status_code == 401
