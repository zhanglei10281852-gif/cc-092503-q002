from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.errors import ConflictError, NotFoundError
from app.samples.handoff_tokens import key_digest


def _row(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        raise NotFoundError("交接凭证不存在")
    return dict(row)


class HandoffCredentialRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def get(self, credential_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handoff_credentials WHERE id=?", (credential_id,)
        ).fetchone()
        return dict(row) if row else None

    def require(self, credential_id: int) -> dict[str, Any]:
        return _row(self.get(credential_id))

    def list_for_batch(self, batch_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM handoff_credentials WHERE batch_id=? ORDER BY version DESC, id DESC",
                (batch_id,),
            ).fetchall()
        ]

    def current_for_batch(self, batch_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handoff_credentials WHERE batch_id=? ORDER BY version DESC, id DESC LIMIT 1",
            (batch_id,),
        ).fetchone()
        return dict(row) if row else None

    def create(
        self,
        *,
        credential_code: str,
        batch_id: int,
        handoff_party: str,
        version: int,
        secret: str,
        issued_by: int,
        issued_at: str,
        expires_at: str,
        now: str,
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO handoff_credentials
                   (credential_code,batch_id,handoff_party,version,key_digest,status,
                    issued_by,issued_at,expires_at,created_at,updated_at)
               VALUES(?,?,?,?,?,'active',?,?,?,?,?)""",
            (
                credential_code, batch_id, handoff_party, version, key_digest(secret),
                issued_by, issued_at, expires_at, now, now,
            ),
        )
        return self.require(cursor.lastrowid)

    def mark_rotated(self, credential_id: int, now: str) -> None:
        self.connection.execute(
            "UPDATE handoff_credentials SET status='rotated',rotated_at=?,updated_at=? WHERE id=?",
            (now, now, credential_id),
        )

    def mark_revoked(self, credential_id: int, revoked_by: int, reason: str, now: str) -> None:
        self.connection.execute(
            """UPDATE handoff_credentials
               SET status='revoked',revoked_at=?,revoked_by=?,revoke_reason=?,updated_at=?
               WHERE id=?""",
            (now, revoked_by, reason, now, credential_id),
        )


class HandoffReceiptRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def successful_for_credential(self, credential_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handoff_receipts WHERE credential_id=?", (credential_id,)
        ).fetchone()
        return dict(row) if row else None

    def by_id(self, receipt_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handoff_receipts WHERE id=?", (receipt_id,)
        ).fetchone()
        return dict(row) if row else None

    def by_batch_and_key(self, batch_id: int, idempotency_key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handoff_receipts WHERE batch_id=? AND idempotency_key=?",
            (batch_id, idempotency_key),
        ).fetchone()
        return dict(row) if row else None

    def list_for_batch(self, batch_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM handoff_receipts WHERE batch_id=? ORDER BY id",
                (batch_id,),
            ).fetchall()
        ]

    def create(
        self,
        *,
        receipt_code: str,
        credential_id: int,
        credential_version: int,
        batch_id: int,
        handoff_party: str,
        idempotency_key: str,
        expected_count: int,
        accepted_count: int,
        rejected_count: int,
        received_by: int,
        received_at: str,
        note: str,
        now: str,
    ) -> dict[str, Any]:
        try:
            cursor = self.connection.execute(
                """INSERT INTO handoff_receipts
                       (receipt_code,credential_id,credential_version,batch_id,handoff_party,
                        idempotency_key,expected_count,accepted_count,rejected_count,
                        received_by,received_at,note,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    receipt_code, credential_id, credential_version, batch_id, handoff_party,
                    idempotency_key, expected_count, accepted_count, rejected_count,
                    received_by, received_at, note, now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            # 并发/重复扫码下由唯一索引兜底，交由上层重放已有回执
            raise ConflictError("交接回执已存在") from exc
        return dict(
            self.connection.execute(
                "SELECT * FROM handoff_receipts WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
        )

    def add_item(self, *, receipt_id: int, line_no: int, sample_code: str, accepted: bool,
                 quantity: float | None, unit: str | None, reject_reason: str | None,
                 location_id: int | None, sample_id: int | None) -> None:
        self.connection.execute(
            """INSERT INTO handoff_receipt_items
                   (receipt_id,line_no,sample_code,accepted,quantity,unit,reject_reason,
                    location_id,sample_id)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                receipt_id, line_no, sample_code, 1 if accepted else 0, quantity, unit,
                reject_reason, location_id, sample_id,
            ),
        )

    def items(self, receipt_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT i.*,l.code AS location_code
               FROM handoff_receipt_items i
               LEFT JOIN storage_locations l ON l.id=i.location_id
               WHERE i.receipt_id=? ORDER BY i.line_no""",
            (receipt_id,),
        ).fetchall()
        return [dict(row) for row in rows]


class HandoffEventRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def append(self, *, credential_id: int, batch_id: int, receipt_id: int | None,
               actor_user_id: int | None, event_type: str, result: str,
               detail: dict[str, Any], now: str) -> None:
        self.connection.execute(
            """INSERT INTO handoff_events
                   (credential_id,batch_id,receipt_id,actor_user_id,event_type,result,
                    detail_json,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                credential_id, batch_id, receipt_id, actor_user_id, event_type, result,
                json.dumps(detail or {}, ensure_ascii=False, sort_keys=True), now,
            ),
        )

    def trail_for_credential(self, credential_id: int) -> list[dict[str, Any]]:
        return self._hydrate(
            self.connection.execute(
                "SELECT * FROM handoff_events WHERE credential_id=? ORDER BY id",
                (credential_id,),
            ).fetchall()
        )

    def trail_for_batch(self, batch_id: int) -> list[dict[str, Any]]:
        return self._hydrate(
            self.connection.execute(
                "SELECT * FROM handoff_events WHERE batch_id=? ORDER BY id",
                (batch_id,),
            ).fetchall()
        )

    @staticmethod
    def _hydrate(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item.pop("detail_json"))
            result.append(item)
        return result
