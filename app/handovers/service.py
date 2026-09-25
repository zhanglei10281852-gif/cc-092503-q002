from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import (
    BatchClosedError,
    ConflictError,
    CredentialExpiredError,
    CredentialNotFoundError,
    CredentialRevokedError,
    CredentialSupersededError,
    HandoverError,
    HandoverPartyMismatchError,
    HandoverPayloadConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.security import Principal, request_fingerprint
from app.handovers.repository import (
    HandoverCredentialRepository,
    HandoverEventRepository,
    HandoverReceiptRepository,
)
from app.handovers.tokens import build_qr, generate_secret, parse_qr, secret_digest
from app.services.audit import AuditService

# 普通查询中二维码字段的占位输出，绝不回传可重放明文或其摘要。
REDACTED = "***"


@dataclass(frozen=True, slots=True)
class RejectedScan:
    credential_id: int | None
    batch_id: int | None
    reason_code: str
    detail: dict[str, Any]


def attach_reject(exc: HandoverError, rejected: RejectedScan) -> HandoverError:
    """把待落库的拒绝轨迹挂在异常上，待外层事务回滚后在新事务中补写。"""
    exc.rejected_scan = rejected  # type: ignore[attr-defined]
    return exc


class HandoverService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.credentials = HandoverCredentialRepository(connection)
        self.receipts = HandoverReceiptRepository(connection)
        self.events = HandoverEventRepository(connection)
        self.audit = AuditService(connection, self.clock)

    # ---- 批次 -------------------------------------------------------------

    def require_batch(self, batch_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM receipt_batches WHERE id=?", (batch_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("接收批次不存在")
        return dict(row)

    def close_batch(self, principal: Principal, batch_id: int) -> dict[str, Any]:
        principal.require("handovers.issue")
        batch = self.require_batch(batch_id)
        if batch["status"] == "closed":
            return {**batch, "replayed": True}
        now = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE receipt_batches SET status='closed',updated_at=? WHERE id=?", (now, batch_id)
        )
        after = self.require_batch(batch_id)
        self.audit.record(principal, "handover.batch_close", "receipt_batch", str(batch_id), before=batch, after=after)
        return {**after, "replayed": False}

    # ---- 发放 / 轮换 / 撤销 -----------------------------------------------

    def issue(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("handovers.issue")
        batch = self.require_batch(data["batch_id"])
        if batch["status"] == "closed":
            raise BatchClosedError("批次已关闭，不能发放交接凭证")
        existing = self.credentials.latest_for_batch(data["batch_id"])
        if existing is not None:
            if existing["status"] == "active":
                # 有效凭证只能轮换，保证同批次始终只有一枚可扫码的码。
                raise ConflictError(
                    "该批次已有有效交接凭证，请轮换生成新码",
                    context={"existing_credential_id": existing["id"], "latest_status": existing["status"]},
                )
            if existing["status"] == "consumed":
                raise ConflictError("该批次已完成扫码接收，不能再次发放凭证")
            # 最新凭证已撤销：允许重新发放，版本号继续单调递增。
        now_dt = self.clock.now()
        return self._create_credential(
            principal,
            batch,
            from_party=data["from_party"],
            from_party_contact=data.get("from_party_contact", ""),
            to_party=data.get("to_party", ""),
            ttl_minutes=data["ttl_minutes"],
            now_dt=now_dt,
            rotated_from_id=None,
            event_type="credential.issued",
        )

    def rotate(self, principal: Principal, credential_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("handovers.issue")
        current = self.credentials.get(credential_id)
        batch = self.require_batch(current["batch_id"])
        if batch["status"] == "closed":
            raise BatchClosedError("批次已关闭，不能轮换交接凭证")
        if current["status"] == "superseded":
            raise CredentialSupersededError("该凭证版本已被新版本取代，请轮换最新凭证")
        if current["status"] == "revoked":
            raise ConflictError("凭证已撤销，不能轮换")
        if current["status"] == "consumed":
            raise ConflictError("凭证已用于接收入库，不能轮换")
        latest = self.credentials.latest_for_batch(current["batch_id"])
        if latest is None or latest["id"] != current["id"]:
            raise ConflictError("只能轮换批次的最新版本凭证")
        now = to_storage(self.clock.now())
        # 旧版本一律作废（即使已过期），保证单调版本只有一枚有效码。
        self.credentials.mark_status(current["id"], "superseded", now)
        result = self._create_credential(
            principal,
            batch,
            from_party=current["from_party"],
            from_party_contact=current["from_party_contact"],
            to_party=data.get("to_party") if data.get("to_party") is not None else current["to_party"],
            ttl_minutes=data.get("ttl_minutes") or 120,
            now_dt=self.clock.now(),
            rotated_from_id=current["id"],
            event_type="credential.rotated",
            extra_event={"superseded_credential_id": current["id"], "superseded_version": current["version"]},
        )
        return result

    def revoke(self, principal: Principal, credential_id: int, reason: str) -> dict[str, Any]:
        principal.require("handovers.issue")
        credential = self.credentials.get(credential_id)
        if credential["status"] == "consumed":
            raise ConflictError("凭证已用于接收，不能撤销")
        if credential["status"] == "revoked":
            return self.public_credential(credential, replayed=True)
        now = to_storage(self.clock.now())
        self.credentials.revoke(credential_id, principal.user_id, reason, now)
        after = self.credentials.get(credential_id)
        self.events.append(
            event_type="credential.revoked",
            result="success",
            created_at=now,
            actor_user_id=principal.user_id,
            actor_name=principal.display_name,
            credential_id=credential_id,
            batch_id=credential["batch_id"],
            detail={"reason": reason},
        )
        self.audit.record(principal, "handover.credential_revoke", "handover_credential", str(credential_id),
                          before=self.public_credential(credential), after=self.public_credential(after))
        return self.public_credential(after, replayed=False)

    def _create_credential(
        self,
        principal: Principal,
        batch: dict[str, Any],
        *,
        from_party: str,
        from_party_contact: str,
        to_party: str,
        ttl_minutes: int,
        now_dt,
        rotated_from_id: int | None,
        event_type: str,
        extra_event: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        latest = self.credentials.latest_for_batch(batch["id"])
        version = 1 if latest is None else int(latest["version"]) + 1
        now = to_storage(now_dt)
        expires = to_storage(now_dt + timedelta(minutes=ttl_minutes))
        credential_code = f"HCR-{uuid.uuid4().hex[:16]}"
        secret = generate_secret()
        credential = self.credentials.create(
            {
                "credential_code": credential_code,
                "batch_id": batch["id"],
                "version": version,
                "from_party": from_party,
                "from_party_contact": from_party_contact,
                "to_party": to_party,
                "secret_digest": secret_digest(credential_code, secret),
                "secret_hint": f"{secret[:2]}…{secret[-2:]}",
                "issued_by": principal.user_id,
                "issued_at": now,
                "expires_at": expires,
                "rotated_from_id": rotated_from_id,
                "created_at": now,
                "updated_at": now,
            }
        )
        self.events.append(
            event_type=event_type,
            result="success",
            created_at=now,
            actor_user_id=principal.user_id,
            actor_name=principal.display_name,
            credential_id=credential["id"],
            batch_id=batch["id"],
            detail={
                "version": version,
                "from_party": from_party,
                "to_party": to_party,
                "ttl_minutes": ttl_minutes,
                "rotated_from_id": rotated_from_id,
                **(extra_event or {}),
            },
        )
        self.audit.record(
            principal, "handover.credential_issue" if event_type == "credential.issued" else "handover.credential_rotate",
            "handover_credential", str(credential["id"]), after=self.public_credential(credential),
            metadata={"version": version, "rotated_from_id": rotated_from_id},
        )
        # 明文二维码仅此一次随响应返回。
        return {
            **self.public_credential(credential),
            "qr_content": build_qr(credential_code, secret),
        }

    # ---- 扫码接收（幂等）--------------------------------------------------

    def receive(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("handovers.receive")
        now = to_storage(self.clock.now())

        credential_code, secret = parse_qr(data["credential"])
        digest = secret_digest(credential_code, secret)
        credential = self.credentials.by_digest(digest)
        if credential is None or credential["credential_code"] != credential_code:
            raise attach_reject(
                CredentialNotFoundError("二维码无效或不存在"),
                RejectedScan(None, None, "credential_not_found", {}),
            )

        batch = self.require_batch(credential["batch_id"])

        # 已用过：回放原回执，实现重复扫码幂等。优先于状态/有效期判断。
        existing = self.receipts.by_credential(credential["id"])
        if existing is not None:
            return self._replay(principal, credential, existing, data, now)

        # 未使用但状态/批次/有效期异常，各自返回可区分结果；轨迹由路由在事务回滚后补写。
        if credential["status"] == "revoked":
            raise attach_reject(
                CredentialRevokedError("交接凭证已被撤销"),
                RejectedScan(credential["id"], batch["id"], "credential_revoked", {}),
            )
        if credential["status"] == "superseded":
            raise attach_reject(
                CredentialSupersededError("二维码版本已过期，请使用最新版本凭证"),
                RejectedScan(credential["id"], batch["id"], "credential_superseded",
                             {"latest_version": self._latest_version(credential["batch_id"])}),
            )
        expires_at = from_storage(credential["expires_at"])
        if expires_at is not None and expires_at <= self.clock.now():
            raise attach_reject(
                CredentialExpiredError("交接凭证已超过有效期"),
                RejectedScan(credential["id"], batch["id"], "credential_expired", {}),
            )
        if batch["status"] == "closed":
            raise attach_reject(
                BatchClosedError("接收批次已关闭，禁止再次入库"),
                RejectedScan(credential["id"], batch["id"], "batch_closed", {}),
            )

        # 凭证绑定交接方：码上的交出方是不可变事实；接收方若在发放时指定则必须匹配扫码人。
        if credential["to_party"]:
            if credential["to_party"].strip() != principal.display_name.strip() and credential["to_party"].strip() != principal.username:
                raise attach_reject(
                    HandoverPartyMismatchError("当前接收人与凭证指定的接收方不一致"),
                    RejectedScan(credential["id"], batch["id"], "handover_party_mismatch",
                                 {"expected_to_party": credential["to_party"]}),
                )

        location = self.connection.execute(
            "SELECT * FROM storage_locations WHERE id=? AND active=1", (data["location_id"],)
        ).fetchone()
        if location is None:
            raise ValidationError("保管位置不存在或已停用")
        if data.get("custodian_user_id"):
            custodian = self.connection.execute(
                "SELECT id FROM users WHERE id=? AND status='active'", (data["custodian_user_id"],)
            ).fetchone()
            if custodian is None:
                raise ValidationError("保管人不存在或不可用")

        reject_reasons = [item.model_dump() if hasattr(item, "model_dump") else dict(item)
                          for item in data.get("reject_reasons", [])]
        receipt_payload = {
            "expected_count": data["expected_count"],
            "accepted_count": data["accepted_count"],
            "rejected_count": data["rejected_count"],
            "reject_reasons": reject_reasons,
            "location_id": data["location_id"],
            "custodian_user_id": data.get("custodian_user_id"),
            "note": data.get("note", ""),
        }

        receipt_code = f"RCPT-{uuid.uuid4().hex[:16]}"
        try:
            receipt = self.receipts.create(
                {
                    "receipt_code": receipt_code,
                    "credential_id": credential["id"],
                    "batch_id": credential["batch_id"],
                    "credential_version": credential["version"],
                    "from_party": credential["from_party"],
                    "to_party": credential["to_party"] or principal.display_name,
                    **receipt_payload,
                    "received_by": principal.user_id,
                    "payload_digest": request_fingerprint(receipt_payload),
                    "received_at": now,
                    "created_at": now,
                }
            )
        except sqlite3.IntegrityError:
            # 并发下唯一约束兜底：另一请求已用该凭证落库，回放其回执。
            winner = self.receipts.by_credential(credential["id"])
            if winner is not None:
                return self._replay(principal, credential, winner, data, now)
            raise

        # 凭证置为已用；拒收数量累加进批次（接收样品在登记 samples 时另行计数）。
        self.credentials.mark_status(credential["id"], "consumed", now)
        self.connection.execute(
            "UPDATE receipt_batches SET rejected_count=rejected_count+?,updated_at=? WHERE id=?",
            (data["rejected_count"], now, credential["batch_id"]),
        )
        self.events.append(
            event_type="credential.received",
            result="success",
            created_at=now,
            actor_user_id=principal.user_id,
            actor_name=principal.display_name,
            credential_id=credential["id"],
            batch_id=credential["batch_id"],
            receipt_id=receipt["id"],
            detail={"receipt_code": receipt_code, **receipt_payload},
        )
        self.audit.record(
            principal, "handover.receive", "handover_receipt", str(receipt["id"]),
            after=receipt, metadata={"credential_id": credential["id"], "version": credential["version"]},
        )
        return {
            "receipt": receipt,
            "credential": self.public_credential(self.credentials.get(credential["id"])),
            "replayed": False,
        }

    def _replay(self, principal: Principal, credential: dict[str, Any], stored: dict[str, Any],
                data: dict[str, Any], now: str) -> dict[str, Any]:
        fingerprint = request_fingerprint({
            "expected_count": data["expected_count"],
            "accepted_count": data["accepted_count"],
            "rejected_count": data["rejected_count"],
            "reject_reasons": [item.model_dump() if hasattr(item, "model_dump") else dict(item)
                               for item in data.get("reject_reasons", [])],
            "location_id": data["location_id"],
            "custodian_user_id": data.get("custodian_user_id"),
            "note": data.get("note", ""),
        })
        if fingerprint != stored["payload_digest"]:
            raise attach_reject(
                HandoverPayloadConflictError("该凭证已接收，但本次扫码内容与原接收记录不一致"),
                RejectedScan(credential["id"], credential["batch_id"], "handover_payload_conflict",
                             {"stored_receipt_code": stored["receipt_code"]}),
            )
        self.events.append(
            event_type="credential.replayed",
            result="success",
            created_at=now,
            actor_user_id=principal.user_id,
            actor_name=principal.display_name,
            credential_id=credential["id"],
            batch_id=credential["batch_id"],
            receipt_id=stored["id"],
            detail={"receipt_code": stored["receipt_code"]},
        )
        return {
            "receipt": stored,
            "credential": self.public_credential(self.credentials.get(credential["id"])),
            "replayed": True,
        }

    # ---- 查询 / 轨迹 ------------------------------------------------------

    def get_credential(self, principal: Principal, credential_id: int) -> dict[str, Any]:
        principal.require("handovers.issue")
        return self.public_credential(self.credentials.get(credential_id))

    def list_for_batch(self, principal: Principal, batch_id: int) -> dict[str, Any]:
        principal.require("samples.read")
        self.require_batch(batch_id)
        credentials = [self.public_credential(item) for item in self.credentials.list_for_batch(batch_id)]
        receipts = self.receipts.list_for_batch(batch_id)
        return {"batch_id": batch_id, "credentials": credentials, "receipts": receipts}

    def trail(self, principal: Principal, *, credential_id: int | None = None,
              batch_id: int | None = None) -> dict[str, Any]:
        # 完整使用轨迹仅管理员可查。
        principal.require("handovers.trail")
        if credential_id is None and batch_id is None:
            raise ValidationError("必须指定凭证或批次")
        if credential_id is not None:
            credential = self.credentials.get(credential_id)
            events = self.events.trail_for_credential(credential_id)
            return {
                "credential": self.public_credential(credential),
                "receipt": self.receipts.by_credential(credential_id),
                "events": events,
            }
        self.require_batch(batch_id)
        return {"batch_id": batch_id, "events": self.events.trail_for_batch(batch_id)}

    # ---- 内部辅助 ---------------------------------------------------------

    def persist_rejected_scan(self, principal: Principal, rejected: RejectedScan) -> None:
        """在业务事务回滚后的新事务中补写被拒扫码轨迹（轨迹本身必须留痕）。"""
        now = to_storage(self.clock.now())
        self.events.append(
            event_type="credential.scan_rejected",
            result="rejected",
            created_at=now,
            actor_user_id=principal.user_id,
            actor_name=principal.display_name,
            credential_id=rejected.credential_id,
            batch_id=rejected.batch_id,
            detail={"reason": rejected.reason_code, **rejected.detail},
        )

    def _latest_version(self, batch_id: int) -> int | None:
        latest = self.credentials.latest_for_batch(batch_id)
        return latest["version"] if latest else None

    @staticmethod
    def public_credential(credential: dict[str, Any], *, replayed: bool = False) -> dict[str, Any]:
        """普通可见视图：绝不包含二维码明文或可用于重放的摘要/提示。"""
        result = {
            key: value
            for key, value in credential.items()
            if key not in {"secret_digest", "secret_hint"}
        }
        result["secret_digest"] = REDACTED
        result["replayed"] = replayed
        return result
