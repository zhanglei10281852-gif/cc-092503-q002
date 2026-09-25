from __future__ import annotations


class DomainError(Exception):
    status_code = 400
    code = "domain_error"

    def __init__(self, message: str, *, context: dict | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = context or {}
        if code is not None:
            self.code = code


class NotFoundError(DomainError):
    status_code = 404
    code = "not_found"


class ConflictError(DomainError):
    status_code = 409
    code = "conflict"


class AuthenticationError(DomainError):
    status_code = 401
    code = "authentication_failed"


class PermissionDeniedError(DomainError):
    status_code = 403
    code = "permission_denied"


class ValidationError(DomainError):
    status_code = 422
    code = "validation_error"


class AccountLockedError(AuthenticationError):
    code = "account_locked"


class SessionExpiredError(AuthenticationError):
    code = "session_expired"


class HandoverError(ConflictError):
    """交接凭证扫码接收的可区分业务错误，code 由具体场景覆盖。"""


class CredentialNotFoundError(HandoverError):
    status_code = 404
    code = "credential_not_found"


class CredentialExpiredError(HandoverError):
    code = "credential_expired"


class CredentialSupersededError(HandoverError):
    code = "credential_superseded"


class CredentialRevokedError(HandoverError):
    code = "credential_revoked"


class BatchClosedError(HandoverError):
    code = "batch_closed"


class HandoverPartyMismatchError(HandoverError):
    code = "handover_party_mismatch"


class HandoverPayloadConflictError(HandoverError):
    code = "handover_payload_conflict"
