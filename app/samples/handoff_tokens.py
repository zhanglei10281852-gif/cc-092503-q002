from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from app.core.errors import ValidationError

QR_SCHEME = "HND1"


@dataclass(frozen=True, slots=True)
class QrToken:
    credential_id: int
    version: int
    secret: str


def generate_secret() -> str:
    """每次颁发/轮换生成的高熵随机密钥，二维码的可重放部分只存在于此。"""
    return secrets.token_urlsafe(24)


def build_qr_content(credential_id: int, version: int, secret: str) -> str:
    return f"{QR_SCHEME}.{credential_id}.{version}.{secret}"


def key_digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def parse_qr_content(content: str) -> QrToken:
    parts = (content or "").strip().split(".")
    if len(parts) != 4 or parts[0] != QR_SCHEME:
        raise ValidationError("二维码格式不正确")
    try:
        credential_id = int(parts[1])
        version = int(parts[2])
    except ValueError as exc:
        raise ValidationError("二维码格式不正确") from exc
    if credential_id <= 0 or version <= 0 or not parts[3]:
        raise ValidationError("二维码格式不正确")
    return QrToken(credential_id=credential_id, version=version, secret=parts[3])


def verify_secret(secret: str, expected_digest: str) -> bool:
    return hmac.compare_digest(key_digest(secret), expected_digest or "")
