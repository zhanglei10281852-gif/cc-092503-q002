from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient


# ---- 辅助 ---------------------------------------------------------------

def _location(client, headers, code="HC-LOC-01"):
    response = client.post(
        "/api/samples/locations",
        headers=headers,
        json={"code": code, "building": "中心库", "room": "常温间", "cabinet": "甲柜",
              "shelf": "一层", "sensitivity": "normal", "capacity_units": 100},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _batch(client, headers, code="HC-BATCH-01", expected=3):
    response = client.post(
        "/api/samples/batches",
        headers=headers,
        json={"batch_code": code, "project_code": "HC-PROJ", "expected_count": expected},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _login(client, username, password, display_name, role_codes, admin_headers):
    created = client.post(
        "/api/users",
        headers=admin_headers,
        json={"username": username, "password": password, "display_name": display_name,
              "role_codes": role_codes},
    )
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login",
                        json={"username": username, "password": password, "client_label": "tests"})
    assert login.status_code == 200, login.text
    token = login.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _issue(client, headers, batch_id, from_party="野外队甲", to_party="", ttl_minutes=120):
    payload = {"batch_id": batch_id, "from_party": from_party, "ttl_minutes": ttl_minutes}
    if to_party:
        payload["to_party"] = to_party
    response = client.post("/api/handovers/credentials", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _receive_payload(qr, location_id, **overrides):
    payload = {
        "credential": qr,
        "expected_count": 3,
        "accepted_count": 2,
        "rejected_count": 1,
        "reject_reasons": [{"sample_code": "S-0003", "reason": "管体破裂渗漏"}],
        "location_id": location_id,
        "note": "整箱交接",
    }
    payload.update(overrides)
    return payload


# ---- 发放与防泄露 --------------------------------------------------------

def test_issue_returns_qr_once_and_views_never_leak_it(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"])
    issued = _issue(client, admin["headers"], batch["id"])
    assert issued["version"] == 1
    assert issued["status"] == "active"
    assert issued["from_party"] == "野外队甲"
    assert issued["qr_content"].startswith("HC1.HCR-")
    assert issued["secret_digest"] == "***"

    # 凭证详情（发放权限）不回传二维码明文或可重放摘要。
    detail = client.get(f"/api/handovers/credentials/{issued['id']}", headers=admin["headers"])
    assert detail.status_code == 200
    body = detail.json()
    assert "qr_content" not in body
    assert "secret_hint" not in body
    assert body["secret_digest"] == "***"

    # 普通只读账号也能看批次交接清单，但看不到任何可重放内容。
    reader = _login(client, "reader.one", "Reader!23456789", "只读员", ["researcher"], admin["headers"])
    listing = client.get(f"/api/handovers/batches/{batch['id']}", headers=reader)
    assert listing.status_code == 200
    text = listing.text
    assert "qr_content" not in text
    assert issued["qr_content"] not in text
    for credential in listing.json()["credentials"]:
        assert credential["secret_digest"] == "***"
        assert "secret_hint" not in credential


def test_issue_requires_permission(client, admin):
    batch = _batch(client, admin["headers"])
    reader = _login(client, "reader.two", "Reader!23456789", "只读员二", ["researcher"], admin["headers"])
    response = client.post(
        "/api/handovers/credentials",
        headers=reader,
        json={"batch_id": batch["id"], "from_party": "野外队甲"},
    )
    assert response.status_code == 403


# ---- 扫码接收与幂等 ------------------------------------------------------

def test_receive_is_idempotent_and_persists_atomically(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"])
    issued = _issue(client, admin["headers"], batch["id"])

    payload = _receive_payload(issued["qr_content"], location["id"])
    first = client.post("/api/handovers/receive", headers=admin["headers"], json=payload)
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["replayed"] is False
    receipt = first_body["receipt"]
    assert receipt["accepted_count"] == 2
    assert receipt["rejected_count"] == 1
    assert receipt["reject_reasons"] == [{"sample_code": "S-0003", "reason": "管体破裂渗漏"}]
    assert receipt["location_id"] == location["id"]

    # 重复扫码：回放同一回执，不新增数据。
    second = client.post("/api/handovers/receive", headers=admin["headers"], json=payload)
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["replayed"] is True
    assert second_body["receipt"]["id"] == receipt["id"]

    listing = client.get(f"/api/handovers/batches/{batch['id']}", headers=admin["headers"]).json()
    assert len(listing["receipts"]) == 1
    assert listing["credentials"][0]["status"] == "consumed"
    refreshed = client.get(f"/api/sample-operations/batches/{batch['id']}/reconciliation",
                           headers=admin["headers"]).json()
    assert refreshed["batch"]["rejected_count"] == 1


def test_receive_same_credential_different_payload_is_conflict(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"])
    issued = _issue(client, admin["headers"], batch["id"])
    payload = _receive_payload(issued["qr_content"], location["id"])
    first = client.post("/api/handovers/receive", headers=admin["headers"], json=payload)
    assert first.status_code == 200

    changed = _receive_payload(issued["qr_content"], location["id"], accepted_count=3, rejected_count=0,
                               reject_reasons=[])
    conflict = client.post("/api/handovers/receive", headers=admin["headers"], json=changed)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "handover_payload_conflict"


# ---- 可区分的失败结果 ----------------------------------------------------

def test_old_version_returns_superseded(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-ROT")
    v1 = _issue(client, admin["headers"], batch["id"])
    rotated = client.post(f"/api/handovers/credentials/{v1['id']}/rotate",
                          headers=admin["headers"], json={})
    assert rotated.status_code == 201, rotated.text
    v2 = rotated.json()
    assert v2["version"] == 2
    assert v1["qr_content"] != v2["qr_content"]

    old_scan = client.post(
        "/api/handovers/receive", headers=admin["headers"],
        json=_receive_payload(v1["qr_content"], location["id"]),
    )
    assert old_scan.status_code == 409
    assert old_scan.json()["error"]["code"] == "credential_superseded"

    # 新版本可正常接收。
    ok = client.post(
        "/api/handovers/receive", headers=admin["headers"],
        json=_receive_payload(v2["qr_content"], location["id"]),
    )
    assert ok.status_code == 200
    assert ok.json()["replayed"] is False


def test_expired_credential_is_distinguishable(client, admin):
    from app.database import get_connection

    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-EXP")
    issued = _issue(client, admin["headers"], batch["id"], ttl_minutes=1)
    get_connection().execute(
        "UPDATE handover_credentials SET expires_at=? WHERE id=?",
        ("2000-01-01T00:00:00+00:00", issued["id"]),
    )
    response = client.post(
        "/api/handovers/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], location["id"]),
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "credential_expired"


def test_revoked_credential_scan_is_distinguishable_and_can_reissue(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-REV")
    issued = _issue(client, admin["headers"], batch["id"])

    revoked = client.post(f"/api/handovers/credentials/{issued['id']}/revoke",
                          headers=admin["headers"], json={"reason": "野外队追回"})
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    scan = client.post(
        "/api/handovers/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], location["id"]),
    )
    assert scan.status_code == 409
    assert scan.json()["error"]["code"] == "credential_revoked"

    # 撤销未使用凭证后可重新发放，版本号继续单调递增。
    reissued = _issue(client, admin["headers"], batch["id"])
    assert reissued["version"] == 2
    ok = client.post(
        "/api/handovers/receive", headers=admin["headers"],
        json=_receive_payload(reissued["qr_content"], location["id"]),
    )
    assert ok.status_code == 200


def test_consumed_credential_cannot_be_revoked(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-USED")
    issued = _issue(client, admin["headers"], batch["id"])
    client.post("/api/handovers/receive", headers=admin["headers"],
                json=_receive_payload(issued["qr_content"], location["id"]))
    revoke = client.post(f"/api/handovers/credentials/{issued['id']}/revoke",
                         headers=admin["headers"], json={"reason": "迟来的撤销"})
    assert revoke.status_code == 409


def test_closed_batch_rejects_scan(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-CLOSED")
    issued = _issue(client, admin["headers"], batch["id"])
    closed = client.post(f"/api/handovers/batches/{batch['id']}/close", headers=admin["headers"])
    assert closed.status_code == 200
    scan = client.post(
        "/api/handovers/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], location["id"]),
    )
    assert scan.status_code == 409
    assert scan.json()["error"]["code"] == "batch_closed"


def test_completed_receipt_replays_even_after_batch_closed_or_expiry(client, admin):
    from app.database import get_connection

    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-IDEMP")
    issued = _issue(client, admin["headers"], batch["id"])
    payload = _receive_payload(issued["qr_content"], location["id"])
    first = client.post("/api/handovers/receive", headers=admin["headers"], json=payload)
    assert first.status_code == 200
    receipt_id = first.json()["receipt"]["id"]

    # 批次关闭、凭证过期都不应改变已完成交接的重复扫码结果。
    client.post(f"/api/handovers/batches/{batch['id']}/close", headers=admin["headers"])
    get_connection().execute(
        "UPDATE handover_credentials SET expires_at=? WHERE id=?",
        ("2000-01-01T00:00:00+00:00", issued["id"]),
    )
    replay = client.post("/api/handovers/receive", headers=admin["headers"], json=payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["receipt"]["id"] == receipt_id


def test_unknown_or_garbage_qr_is_not_found(client, admin):
    location = _location(client, admin["headers"])
    for raw in ("HC1.HCR-doesnotexist.aaaaaaaaaaaaaaaaaaaa", "这是随便乱扫的无效二维码内容"):
        response = client.post(
            "/api/handovers/receive", headers=admin["headers"],
            json=_receive_payload(raw, location["id"]),
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "credential_not_found"


def test_designated_receiver_is_enforced(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-PARTY")
    issued = _issue(client, admin["headers"], batch["id"], to_party="中心库接收员甲")
    response = client.post(
        "/api/handovers/receive", headers=admin["headers"],
        json=_receive_payload(issued["qr_content"], location["id"]),
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "handover_party_mismatch"


# ---- 轨迹与权限 ----------------------------------------------------------

def test_admin_trail_records_full_lifecycle_and_hides_secret(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-TRAIL")
    v1 = _issue(client, admin["headers"], batch["id"])
    rotated = client.post(f"/api/handovers/credentials/{v1['id']}/rotate",
                          headers=admin["headers"], json={})
    assert rotated.status_code == 201, rotated.text
    qr_v2 = rotated.json()["qr_content"]

    payload = _receive_payload(qr_v2, location["id"])
    client.post("/api/handovers/receive", headers=admin["headers"], json=payload)
    client.post("/api/handovers/receive", headers=admin["headers"], json=payload)  # 重复扫码回放

    trail = client.get(f"/api/handovers/batches/{batch['id']}/trail", headers=admin["headers"])
    assert trail.status_code == 200
    events = trail.json()["events"]
    kinds = {event["event_type"] for event in events}
    assert {"credential.issued", "credential.rotated", "credential.received", "credential.replayed"} <= kinds
    text = trail.text
    assert "qr_content" not in text
    assert "secret_hint" not in text

    # 扫一次旧版本码，轨迹中应留下被拒记录。
    client.post("/api/handovers/receive", headers=admin["headers"],
                json=_receive_payload(v1["qr_content"], location["id"]))
    trail_after = client.get(f"/api/handovers/batches/{batch['id']}/trail", headers=admin["headers"]).json()
    rejected = [e for e in trail_after["events"] if e["event_type"] == "credential.scan_rejected"]
    assert rejected and rejected[-1]["detail"]["reason"] == "credential_superseded"

    # 样品管理员有发放/接收权，但看不到管理员级完整轨迹。
    manager = _login(client, "manager.one", "Manager!234567", "样品管理员", ["sample_manager"], admin["headers"])
    forbidden = client.get(f"/api/handovers/batches/{batch['id']}/trail", headers=manager)
    assert forbidden.status_code == 403


# ---- 并发交接 ------------------------------------------------------------

def test_concurrent_receives_exactly_one_wins(client, admin):
    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-CONC")
    issued = _issue(client, admin["headers"], batch["id"])
    payload = _receive_payload(issued["qr_content"], location["id"])
    token = admin["headers"]["Authorization"]

    barrier = threading.Barrier(5)

    def worker():
        from app.main import app as handover_app
        from app.database import close_connection

        local_client = TestClient(handover_app)  # 不触发 lifespan，复用已初始化的库文件
        barrier.wait()
        response = local_client.post("/api/handovers/receive",
                                     headers={"Authorization": token}, json=payload)
        close_connection()
        return response.status_code, response.json()

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: worker(), range(5)))

    assert all(status == 200 for status, _ in results)
    winners = [body for _, body in results if not body["replayed"]]
    replays = [body for _, body in results if body["replayed"]]
    assert len(winners) == 1
    assert len(replays) == 4
    receipt_ids = {body["receipt"]["id"] for _, body in results}
    assert len(receipt_ids) == 1

    listing = client.get(f"/api/handovers/batches/{batch['id']}", headers=admin["headers"]).json()
    assert len(listing["receipts"]) == 1
    assert listing["receipts"][0]["rejected_count"] == 1  # 拒收数未被重复累加


# ---- 服务重启后的结果 ----------------------------------------------------

def test_result_survives_service_restart(client, admin):
    from app.database import close_connection
    from app.main import app

    location = _location(client, admin["headers"])
    batch = _batch(client, admin["headers"], code="HC-BATCH-RESTART")
    issued = _issue(client, admin["headers"], batch["id"])
    payload = _receive_payload(issued["qr_content"], location["id"])
    first = client.post("/api/handovers/receive", headers=admin["headers"], json=payload)
    assert first.status_code == 200
    receipt_id = first.json()["receipt"]["id"]

    # 丢弃进程内连接并重新走一遍 lifespan，等价于服务重启。
    close_connection()
    with TestClient(app) as restarted:
        replay = restarted.post("/api/handovers/receive", headers=admin["headers"], json=payload)
        assert replay.status_code == 200
        assert replay.json()["replayed"] is True
        assert replay.json()["receipt"]["id"] == receipt_id

        # 重启后旧版本/凭证状态判定依旧成立。
        another_batch = _batch(client, admin["headers"], code="HC-BATCH-RESTART-2")
        credential = _issue(restarted, admin["headers"], another_batch["id"])
        restarted.post(f"/api/handovers/batches/{another_batch['id']}/close",
                       headers=admin["headers"])
        closed_scan = restarted.post(
            "/api/handovers/receive", headers=admin["headers"],
            json=_receive_payload(credential["qr_content"], location["id"]),
        )
        assert closed_scan.json()["error"]["code"] == "batch_closed"
