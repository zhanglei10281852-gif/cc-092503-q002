from __future__ import annotations

import sqlite3
import uuid
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import (
    BatchClosedError,
    BatchQuarantinedError,
    ConflictError,
    CredentialExpiredError,
    CredentialRevokedError,
    CredentialUnknownError,
    CredentialUsedError,
    CredentialVersionStaleError,
    DomainError,
    HandoffPartyMismatchError,
    NotFoundError,
)
from app.core.security import Principal
from app.database import transaction as db_transaction
from app.samples.handoff_repository import (
    HandoffCredentialRepository,
    HandoffEventRepository,
    HandoffReceiptRepository,
)
from app.samples.handoff_tokens import (
    build_qr_content,
    generate_secret,
    parse_qr_content,
    verify_secret,
)
from app.samples.repository import LocationRepository, SampleRepository
from app.services.audit import AuditService

DEFAULT_TTL_MINUTES = 120


class HandoffService:
    """交接二维码凭证的颁发、轮换、撤销、扫码接收与轨迹查询。

    连接为线程局部单例，因此本服务不嵌套事务：只读判定直接走自动提交连接，
    被拒绝的扫码用独立短事务留痕后再抛出可区分异常。
    """

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()

    # ---- 凭证颁发 / 轮换 / 撤销 -------------------------------------------------

    def issue(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("handoffs.issue")
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        with db_transaction(immediate=True) as connection:
            creds, receipts, events, audit = self._bind(connection)
            batch = self._require_batch(data["batch_id"])
            if batch["status"] in {"closed", "quarantined"}:
                raise ConflictError("批次已关闭或隔离，不能颁发交接凭证")
            if creds.list_for_batch(batch["id"]):
                raise ConflictError("批次已存在交接凭证，请使用轮换接口")
            secret = generate_secret()
            credential = creds.create(
                credential_code=f"HND-{uuid.uuid4().hex[:12]}",
                batch_id=batch["id"],
                handoff_party=data["handoff_party"].strip(),
                version=1,
                secret=secret,
                issued_by=principal.user_id,
                issued_at=now,
                expires_at=to_storage(now_dt + timedelta(minutes=data["ttl_minutes"])),
                now=now,
            )
            events.append(
                credential_id=credential["id"], batch_id=batch["id"], receipt_id=None,
                actor_user_id=principal.user_id, event_type="credential.issued",
                result="success",
                detail={"version": 1, "handoff_party": credential["handoff_party"],
                        "expires_at": credential["expires_at"]},
                now=now,
            )
            audit.record(principal, "handoff.credential.issue", "handoff_credential",
                         credential["id"], after=self.public_view(credential))
            result = self.public_view(credential)
            result["qr_content"] = build_qr_content(credential["id"], credential["version"], secret)
            return result

    def rotate(self, principal: Principal, batch_id: int, ttl_minutes: int | None) -> dict[str, Any]:
        principal.require("handoffs.issue")
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        ttl = ttl_minutes or DEFAULT_TTL_MINUTES
        with db_transaction(immediate=True) as connection:
            creds, receipts, events, audit = self._bind(connection)
            batch = self._require_batch(batch_id)
            if batch["status"] in {"closed", "quarantined"}:
                raise ConflictError("批次已关闭或隔离，不能轮换交接凭证")
            current = creds.current_for_batch(batch["id"])
            if current is None:
                raise NotFoundError("该批次尚未颁发交接凭证")
            if receipts.list_for_batch(batch["id"]):
                raise ConflictError("批次已完成交接，不能再轮换凭证")
            if current["status"] == "active":
                # 旧版本立即作废；之后扫旧码命中 rotated 行，返回版本失效。
                creds.mark_rotated(current["id"], now)
            secret = generate_secret()
            version = int(current["version"]) + 1
            credential = creds.create(
                credential_code=f"HND-{uuid.uuid4().hex[:12]}",
                batch_id=batch["id"],
                handoff_party=current["handoff_party"],
                version=version,
                secret=secret,
                issued_by=principal.user_id,
                issued_at=now,
                expires_at=to_storage(now_dt + timedelta(minutes=ttl)),
                now=now,
            )
            events.append(
                credential_id=credential["id"], batch_id=batch["id"], receipt_id=None,
                actor_user_id=principal.user_id, event_type="credential.rotated",
                result="success",
                detail={"version": version, "previous_version": current["version"],
                        "previous_status": current["status"],
                        "expires_at": credential["expires_at"]},
                now=now,
            )
            audit.record(principal, "handoff.credential.rotate", "handoff_credential",
                         credential["id"], after=self.public_view(credential),
                         metadata={"previous_version": current["version"]})
            result = self.public_view(credential)
            result["qr_content"] = build_qr_content(credential["id"], credential["version"], secret)
            return result

    def revoke(self, principal: Principal, credential_id: int, reason: str) -> dict[str, Any]:
        principal.require("handoffs.revoke")
        now = to_storage(self.clock.now())
        with db_transaction(immediate=True) as connection:
            creds, receipts, events, audit = self._bind(connection)
            credential = creds.require(credential_id)
            if credential["status"] != "active":
                raise ConflictError("只有未使用的有效凭证可以撤销")
            if receipts.successful_for_credential(credential_id) is not None:
                raise ConflictError("凭证已用于交接，不能撤销")
            creds.mark_revoked(credential_id, principal.user_id, reason.strip(), now)
            updated = creds.require(credential_id)
            events.append(
                credential_id=credential_id, batch_id=credential["batch_id"], receipt_id=None,
                actor_user_id=principal.user_id, event_type="credential.revoked",
                result="success", detail={"reason": reason.strip()}, now=now,
            )
            audit.record(principal, "handoff.credential.revoke", "handoff_credential",
                         credential_id, after=self.public_view(updated),
                         metadata={"reason": reason.strip()})
            return self.public_view(updated)

    # ---- 扫码接收 -------------------------------------------------------------

    def receive(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("handoffs.receive")
        token = parse_qr_content(data["qr_content"])
        now = to_storage(self.clock.now())

        # 自动提交连接上的只读判定。
        credential = HandoffCredentialRepository(self.connection).get(token.credential_id)
        if credential is None or not verify_secret(token.secret, credential["key_digest"]):
            self._record_denied(principal, None, None, None, "receive.unknown",
                                {"reason": "credential_unknown", "credential_id": token.credential_id})
            raise CredentialUnknownError("二维码凭证不存在或已失效")

        # 成功回执优先：同一幂等键的重复/重试扫码一律原样返回，不再受时效闸门影响。
        existing = HandoffReceiptRepository(self.connection).by_batch_and_key(
            credential["batch_id"], data["idempotency_key"]
        )
        if existing is not None:
            return self._receipt_response(existing, replayed=True)

        # 其余拒绝原因（旧版本、撤销、过期、交接方、批次状态）独立留痕后抛出。
        self._enforce_gate(credential, token.version, data, principal, write_trail=True)

        pending_error: DomainError | None = None
        response: dict[str, Any] | None = None
        with db_transaction(immediate=True) as connection:
            creds, receipts, events, _audit = self._bind(connection)
            samples = SampleRepository(connection)
            locations = LocationRepository(connection)

            credential = creds.require(token.credential_id)
            batch = self._require_batch(credential["batch_id"])
            # 拿写锁后状态可能已变化，锁内再判定一次；事件随本事务正常提交。
            pending_error = self._gate_error(credential, batch, token.version, data)
            if pending_error is not None:
                events.append(
                    credential_id=credential["id"], batch_id=batch["id"], receipt_id=None,
                    actor_user_id=principal.user_id,
                    event_type=self._event_type_for(pending_error), result="denied",
                    detail=self._detail_for(pending_error, credential, token.version, data),
                    now=now,
                )
            else:
                response, pending_error = self._persist_receipt(
                    principal, data, credential, batch, now,
                    creds, receipts, events, samples, locations,
                )

        if pending_error is not None:
            raise pending_error
        assert response is not None
        return response

    def _persist_receipt(
        self, principal, data, credential, batch, now,
        creds, receipts, events, samples, locations,
    ) -> tuple[dict[str, Any] | None, DomainError | None]:
        # 锁内先重查幂等键：并发下同键请求在此得到回放而不是冲突。
        existing = receipts.by_batch_and_key(batch["id"], data["idempotency_key"])
        if existing is not None:
            return self._receipt_response(existing, replayed=True), None
        # 同一凭证已有成功回执，且不是本幂等键：拒绝重放。
        occupied = receipts.successful_for_credential(credential["id"])
        if occupied is not None:
            events.append(
                credential_id=credential["id"], batch_id=batch["id"], receipt_id=None,
                actor_user_id=principal.user_id, event_type="receive.already_used",
                result="denied", detail={"existing_receipt_id": occupied["id"]}, now=now,
            )
            return None, CredentialUsedError("该二维码凭证已完成交接，不能重复使用")

        items = data["items"]
        accepted_items = [item for item in items if item["accepted"]]
        for item in accepted_items:
            if samples.by_code(item["sample_code"]):
                # 业务校验失败：交由事务回滚，不落轨迹。
                raise ConflictError(f"样品编码已经存在：{item['sample_code']}")
            locations.get(item["location_id"])

        try:
            receipt = receipts.create(
                receipt_code=f"RCP-{uuid.uuid4().hex[:12]}",
                credential_id=credential["id"],
                credential_version=credential["version"],
                batch_id=batch["id"],
                handoff_party=credential["handoff_party"],
                idempotency_key=data["idempotency_key"],
                expected_count=data["expected_count"],
                accepted_count=len(accepted_items),
                rejected_count=len(items) - len(accepted_items),
                received_by=principal.user_id,
                received_at=now,
                note=data.get("note", ""),
                now=now,
            )
        except ConflictError:
            # 并发竞争由唯一索引兜底：同键回放，异键拒绝。
            raced = receipts.by_batch_and_key(batch["id"], data["idempotency_key"])
            if raced is not None:
                return self._receipt_response(raced, replayed=True), None
            occupied = receipts.successful_for_credential(credential["id"])
            events.append(
                credential_id=credential["id"], batch_id=batch["id"], receipt_id=None,
                actor_user_id=principal.user_id, event_type="receive.concurrent",
                result="denied",
                detail={"existing_receipt_id": occupied["id"] if occupied else None},
                now=now,
            )
            return None, CredentialUsedError("交接正在被并发处理，该凭证已被占用")

        for item in items:
            sample_id = None
            if item["accepted"]:
                sample = samples.create(
                    {
                        "sample_code": item["sample_code"],
                        "batch_id": batch["id"],
                        "collection_event_id": None,
                        "parent_sample_id": None,
                        "root_sample_id": None,
                        "sample_type": item["sample_type"],
                        "quantity": item["quantity"],
                        "unit": item["unit"],
                        "lifecycle_state": "available",
                        "location_id": item["location_id"],
                        "custody_user_id": principal.user_id,
                        "lineage_depth": 0,
                    },
                    now,
                )
                sample_id = sample["id"]
                samples.append_event(
                    sample["id"], "received", principal.user_id, now,
                    to_state="available",
                    details={"batch_id": batch["id"], "receipt_id": receipt["id"],
                             "handoff_party": credential["handoff_party"]},
                )
            receipts.add_item(
                receipt_id=receipt["id"], line_no=item["line_no"],
                sample_code=item["sample_code"], accepted=item["accepted"],
                quantity=item.get("quantity"), unit=item.get("unit"),
                reject_reason=item.get("reject_reason"), location_id=item.get("location_id"),
                sample_id=sample_id,
            )

        self._refresh_batch_counts(batch["id"], now)
        events.append(
            credential_id=credential["id"], batch_id=batch["id"], receipt_id=receipt["id"],
            actor_user_id=principal.user_id, event_type="receipt.created",
            result="success",
            detail={"receipt_code": receipt["receipt_code"],
                    "accepted": len(accepted_items),
                    "rejected": len(items) - len(accepted_items)},
            now=now,
        )
        AuditService(self.connection, self.clock).record(
            principal, "handoff.receive", "handoff_receipt", receipt["id"],
            after={"receipt_code": receipt["receipt_code"], "batch_id": batch["id"],
                   "accepted_count": receipt["accepted_count"],
                   "rejected_count": receipt["rejected_count"]},
            metadata={"credential_id": credential["id"], "credential_version": credential["version"]},
        )
        return self._receipt_response(receipt, replayed=False), None

    # ---- 查询 / 轨迹 -----------------------------------------------------------

    def list_credentials(self, principal: Principal, batch_id: int) -> list[dict[str, Any]]:
        principal.require("handoffs.read")
        self._require_batch(batch_id)
        creds = HandoffCredentialRepository(self.connection)
        return [self.public_view(item) for item in creds.list_for_batch(batch_id)]

    def credential_detail(self, principal: Principal, credential_id: int) -> dict[str, Any]:
        principal.require("handoffs.read")
        with db_transaction() as connection:
            creds = HandoffCredentialRepository(connection)
            events = HandoffEventRepository(connection)
            credential = creds.require(credential_id)
            result = self.public_view(credential)
            result["trail"] = events.trail_for_credential(credential_id)
            return result

    def batch_trail(self, principal: Principal, batch_id: int) -> dict[str, Any]:
        principal.require("handoffs.read")
        with db_transaction() as connection:
            creds = HandoffCredentialRepository(connection)
            receipts = HandoffReceiptRepository(connection)
            events = HandoffEventRepository(connection)
            batch = self._require_batch(batch_id)
            return {
                "batch": {"id": batch["id"], "batch_code": batch["batch_code"],
                          "status": batch["status"], "expected_count": batch["expected_count"],
                          "accepted_count": batch["accepted_count"],
                          "rejected_count": batch["rejected_count"]},
                "credentials": [self.public_view(item) for item in creds.list_for_batch(batch_id)],
                "receipts": [self._receipt_view(receipts, item) for item in receipts.list_for_batch(batch_id)],
                "events": events.trail_for_batch(batch_id),
            }

    # ---- 闸门与留痕 -------------------------------------------------------------

    def _enforce_gate(self, credential: dict[str, Any], version: int,
                      data: dict[str, Any], principal: Principal, *, write_trail: bool) -> None:
        batch = self.connection.execute(
            "SELECT * FROM receipt_batches WHERE id=?", (credential["batch_id"],)
        ).fetchone()
        batch_dict = dict(batch) if batch is not None else None
        error = self._gate_error(credential, batch_dict, version, data)
        if error is None:
            return
        if write_trail:
            self._record_denied(
                principal, credential["id"], credential["batch_id"], None,
                self._event_type_for(error),
                self._detail_for(error, credential, version, data),
            )
        raise error

    def _gate_error(
        self,
        credential: dict[str, Any],
        batch: dict[str, Any] | None,
        version: int,
        data: dict[str, Any],
    ) -> DomainError | None:
        # 旧码指向已作废行；版本字段被改动也视为旧版本。
        if credential["status"] == "rotated" or version != int(credential["version"]):
            return CredentialVersionStaleError("二维码版本已失效，请使用最新版本")
        if credential["status"] == "revoked":
            return CredentialRevokedError("二维码凭证已被撤销")
        expires_at = from_storage(credential["expires_at"])
        if expires_at is not None and expires_at <= self.clock.now():
            return CredentialExpiredError("二维码凭证已过期")
        if data["handoff_party"].strip() != credential["handoff_party"]:
            return HandoffPartyMismatchError("交接方与凭证绑定的交接方不一致")
        if batch is not None and batch["status"] == "closed":
            return BatchClosedError("接收批次已关闭，不能再次扫码入库")
        if batch is not None and batch["status"] == "quarantined":
            return BatchQuarantinedError("接收批次已隔离，暂停接收")
        return None

    @staticmethod
    def _event_type_for(error: DomainError) -> str:
        return {
            "credential_version_stale": "receive.version_stale",
            "credential_revoked": "receive.revoked",
            "credential_expired": "receive.expired",
            "handoff_party_mismatch": "receive.party_mismatch",
            "batch_closed": "receive.batch_closed",
            "batch_quarantined": "receive.batch_quarantined",
        }.get(error.code, "receive.denied")

    def _detail_for(self, error: DomainError, credential: dict[str, Any],
                    version: int, data: dict[str, Any]) -> dict[str, Any]:
        if error.code == "credential_version_stale":
            return {"presented_version": version, "row_status": credential["status"]}
        if error.code == "credential_expired":
            return {"expires_at": credential["expires_at"]}
        if error.code == "handoff_party_mismatch":
            return {"presented_party": data["handoff_party"].strip(),
                    "bound_party": credential["handoff_party"]}
        return {"credential_status": credential["status"]}

    def _record_denied(self, principal: Principal, credential_id: int | None,
                       batch_id: int | None, receipt_id: int | None,
                       event_type: str, detail: dict[str, Any]) -> None:
        """被拒绝扫码的轨迹与审计用独立短事务立即提交，不随业务事务回滚。"""
        with db_transaction(immediate=True) as connection:
            if credential_id is not None:
                HandoffEventRepository(connection).append(
                    credential_id=credential_id, batch_id=batch_id, receipt_id=receipt_id,
                    actor_user_id=principal.user_id, event_type=event_type, result="denied",
                    detail=detail, now=to_storage(self.clock.now()),
                )
            AuditService(connection, self.clock).record(
                principal, "handoff.receive.denied", "handoff_credential",
                credential_id, outcome="denied", metadata=detail,
            )

    # ---- 辅助 -------------------------------------------------------------------

    def _bind(self, connection: sqlite3.Connection):
        return (
            HandoffCredentialRepository(connection),
            HandoffReceiptRepository(connection),
            HandoffEventRepository(connection),
            AuditService(connection, self.clock),
        )

    def _require_batch(self, batch_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM receipt_batches WHERE id=?", (batch_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("接收批次不存在")
        return dict(row)

    def _refresh_batch_counts(self, batch_id: int, now: str) -> None:
        accepted = self.connection.execute(
            "SELECT COUNT(*) FROM samples WHERE batch_id=?", (batch_id,)
        ).fetchone()[0]
        rejected = self.connection.execute(
            """SELECT COUNT(*) FROM handoff_receipt_items i
               JOIN handoff_receipts r ON r.id=i.receipt_id
               WHERE r.batch_id=? AND i.accepted=0""",
            (batch_id,),
        ).fetchone()[0]
        self.connection.execute(
            "UPDATE receipt_batches SET accepted_count=?,rejected_count=?,updated_at=? WHERE id=?",
            (accepted, rejected, now, batch_id),
        )

    @staticmethod
    def public_view(credential: dict[str, Any]) -> dict[str, Any]:
        """任何查询都不回传密钥哈希；二维码原文仅在颁发/轮换响应中出现一次。"""
        return {key: value for key, value in credential.items() if key != "key_digest"}

    def _receipt_view(self, receipts: HandoffReceiptRepository, receipt: dict[str, Any]) -> dict[str, Any]:
        result = dict(receipt)
        result["items"] = receipts.items(receipt["id"])
        return result

    def _receipt_response(self, receipt: dict[str, Any], *, replayed: bool) -> dict[str, Any]:
        receipts = HandoffReceiptRepository(self.connection)
        return {"replayed": replayed, "receipt": self._receipt_view(receipts, receipt)}
