from __future__ import annotations

import hashlib
import secrets

from app.core.errors import CredentialNotFoundError

QR_SCHEME = "HC1"


def generate_secret(num_bytes: int = 32) -> str:
    return secrets.token_urlsafe(num_bytes)


def build_qr(credential_code: str, secret: str) -> str:
    return f"{QR_SCHEME}.{credential_code}.{secret}"


def secret_digest(credential_code: str, secret: str) -> str:
    """二维码明文不落库，仅保存其摘要。"""
    return hashlib.sha256(f"{credential_code}:{secret}".encode("utf-8")).hexdigest()


def parse_qr(token: str) -> tuple[str, str]:
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != QR_SCHEME or not parts[1] or not parts[2]:
        raise CredentialNotFoundError("二维码内容无法识别")
    return parts[1], parts[2]
