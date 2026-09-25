from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.dependencies import current_principal
from app.core.errors import HandoverError
from app.core.security import Principal
from app.database import get_connection, transaction
from app.handovers.schemas import (
    CredentialIssue,
    CredentialRevoke,
    CredentialRotate,
    HandoverReceive,
)
from app.handovers.service import HandoverService

router = APIRouter(prefix="/api/handovers", tags=["样品交接"])


@router.post("/batches/{batch_id}/close")
def close_batch(batch_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return HandoverService(connection).close_batch(principal, batch_id)


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
def issue_credential(payload: CredentialIssue, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return HandoverService(connection).issue(principal, payload.model_dump())


@router.post("/credentials/{credential_id}/rotate", status_code=status.HTTP_201_CREATED)
def rotate_credential(credential_id: int, payload: CredentialRotate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return HandoverService(connection).rotate(principal, credential_id, payload.model_dump(exclude_unset=True))


@router.post("/credentials/{credential_id}/revoke")
def revoke_credential(credential_id: int, payload: CredentialRevoke, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return HandoverService(connection).revoke(principal, credential_id, payload.reason)


@router.get("/credentials/{credential_id}")
def get_credential(credential_id: int, principal: Principal = Depends(current_principal)):
    return HandoverService(get_connection()).get_credential(principal, credential_id)


@router.get("/batches/{batch_id}")
def list_batch_handovers(batch_id: int, principal: Principal = Depends(current_principal)):
    return HandoverService(get_connection()).list_for_batch(principal, batch_id)


@router.get("/credentials/{credential_id}/trail")
def credential_trail(credential_id: int, principal: Principal = Depends(current_principal)):
    return HandoverService(get_connection()).trail(principal, credential_id=credential_id)


@router.get("/batches/{batch_id}/trail")
def batch_trail(batch_id: int, principal: Principal = Depends(current_principal)):
    return HandoverService(get_connection()).trail(principal, batch_id=batch_id)


@router.post("/receive")
def receive_by_qr(payload: HandoverReceive, principal: Principal = Depends(current_principal)):
    try:
        with transaction(immediate=True) as connection:
            return HandoverService(connection).receive(principal, payload.model_dump())
    except HandoverError as exc:
        rejected = getattr(exc, "rejected_scan", None)
        if rejected is not None:
            # 业务事务已随异常回滚；在独立新事务中留痕，再原样返回可区分错误码。
            with transaction(immediate=True) as connection:
                HandoverService(connection).persist_rejected_scan(principal, rejected)
        raise
