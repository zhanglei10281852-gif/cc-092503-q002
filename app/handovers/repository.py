from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.errors import NotFoundError


class HandoverCredentialRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create(self, values: dict[str, Any]) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO handover_credentials(
                   credential_code,batch_id,version,from_party,from_party_contact,to_party,
                   secret_digest,secret_hint,status,issued_by,issued_at,expires_at,
                   rotated_from_id,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                values["credential_code"], values["batch_id"], values["version"],
                values["from_party"], values.get("from_party_contact", ""), values.get("to_party", ""),
                values["secret_digest"], values.get("secret_hint", ""), "active",
                values["issued_by"], values["issued_at"], values["expires_at"],
                values.get("rotated_from_id"), values["created_at"], values["updated_at"],
            ),
        )
        return self.get(cursor.lastrowid)

    def get(self, credential_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM handover_credentials WHERE id=?", (credential_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("交接凭证不存在")
        return dict(row)

    def by_code(self, credential_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handover_credentials WHERE credential_code=?", (credential_code,)
        ).fetchone()
        return dict(row) if row else None

    def by_digest(self, secret_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handover_credentials WHERE secret_digest=?", (secret_digest,)
        ).fetchone()
        return dict(row) if row else None

    def latest_for_batch(self, batch_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handover_credentials WHERE batch_id=? ORDER BY version DESC LIMIT 1",
            (batch_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_for_batch(self, batch_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM handover_credentials WHERE batch_id=? ORDER BY version", (batch_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def mark_status(self, credential_id: int, status: str, now: str) -> None:
        self.connection.execute(
            "UPDATE handover_credentials SET status=?,updated_at=? WHERE id=?",
            (status, now, credential_id),
        )

    def revoke(self, credential_id: int, revoked_by: int, reason: str, now: str) -> None:
        self.connection.execute(
            """UPDATE handover_credentials
               SET status='revoked',revoked_by=?,revoked_at=?,revoke_reason=?,updated_at=?
               WHERE id=?""",
            (revoked_by, now, reason, now, credential_id),
        )


class HandoverReceiptRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create(self, values: dict[str, Any]) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO handover_receipts(
                   receipt_code,credential_id,batch_id,credential_version,from_party,to_party,
                   expected_count,accepted_count,rejected_count,reject_reasons_json,
                   location_id,received_by,custodian_user_id,note,payload_digest,received_at,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                values["receipt_code"], values["credential_id"], values["batch_id"],
                values["credential_version"], values["from_party"], values["to_party"],
                values["expected_count"], values["accepted_count"], values["rejected_count"],
                json.dumps(values["reject_reasons"], ensure_ascii=False),
                values["location_id"], values["received_by"], values.get("custodian_user_id"),
                values.get("note", ""), values["payload_digest"],
                values["received_at"], values["created_at"],
            ),
        )
        return self.get(cursor.lastrowid)

    def get(self, receipt_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM handover_receipts WHERE id=?", (receipt_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("交接回执不存在")
        result = dict(row)
        result["reject_reasons"] = json.loads(result.pop("reject_reasons_json"))
        return result

    def by_credential(self, credential_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM handover_receipts WHERE credential_id=?", (credential_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["reject_reasons"] = json.loads(result.pop("reject_reasons_json"))
        return result

    def list_for_batch(self, batch_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM handover_receipts WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["reject_reasons"] = json.loads(item.pop("reject_reasons_json"))
            result.append(item)
        return result


class HandoverEventRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def append(
        self,
        *,
        event_type: str,
        result: str,
        created_at: str,
        actor_user_id: int | None = None,
        actor_name: str = "系统",
        credential_id: int | None = None,
        batch_id: int | None = None,
        receipt_id: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO handover_events(
                   credential_id,batch_id,receipt_id,actor_user_id,actor_name,
                   event_type,result,detail_json,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                credential_id, batch_id, receipt_id, actor_user_id, actor_name,
                event_type, result, json.dumps(detail or {}, ensure_ascii=False), created_at,
            ),
        )
        return cursor.lastrowid

    def trail_for_credential(self, credential_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM handover_events WHERE credential_id=? ORDER BY id", (credential_id,)
        ).fetchall()
        return [self._load(row) for row in rows]

    def trail_for_batch(self, batch_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM handover_events WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall()
        return [self._load(row) for row in rows]

    @staticmethod
    def _load(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["detail"] = json.loads(item.pop("detail_json"))
        return item
