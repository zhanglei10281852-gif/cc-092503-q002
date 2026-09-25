from __future__ import annotations


class DomainError(Exception):
    status_code = 400
    code = "domain_error"

    def __init__(self, message: str, *, context: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = context or {}


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


class HandoffError(DomainError):
    """交接扫码类拒绝的基类，具体错误码用于区分不同的拒绝原因。"""


class CredentialUnknownError(HandoffError):
    status_code = 404
    code = "credential_unknown"


class CredentialExpiredError(HandoffError):
    status_code = 410
    code = "credential_expired"


class CredentialVersionStaleError(HandoffError):
    status_code = 409
    code = "credential_version_stale"


class CredentialRevokedError(HandoffError):
    status_code = 409
    code = "credential_revoked"


class CredentialUsedError(HandoffError):
    status_code = 409
    code = "credential_already_used"


class HandoffPartyMismatchError(HandoffError):
    status_code = 409
    code = "handoff_party_mismatch"


class BatchClosedError(HandoffError):
    status_code = 409
    code = "batch_closed"


class BatchQuarantinedError(HandoffError):
    status_code = 409
    code = "batch_quarantined"
