from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection
from app.samples.handoff_schemas import (
    CredentialIssueRequest,
    CredentialRevokeRequest,
    CredentialRotateRequest,
    ReceiptReceiveRequest,
)
from app.samples.handoff_service import HandoffService

router = APIRouter(prefix="/api/handoffs", tags=["批次交接凭证"])


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
def issue_credential(
    payload: CredentialIssueRequest, principal: Principal = Depends(current_principal)
):
    service = HandoffService(get_connection())
    return service.issue(principal, payload.model_dump())


@router.post("/batches/{batch_id}/credentials/rotate", status_code=status.HTTP_201_CREATED)
def rotate_credential(
    batch_id: int,
    payload: CredentialRotateRequest | None = None,
    principal: Principal = Depends(current_principal),
):
    ttl = payload.ttl_minutes if payload is not None else None
    return HandoffService(get_connection()).rotate(principal, batch_id, ttl)


@router.post("/credentials/{credential_id}/revoke")
def revoke_credential(
    credential_id: int,
    payload: CredentialRevokeRequest | None = None,
    principal: Principal = Depends(current_principal),
):
    reason = payload.reason if payload is not None else ""
    return HandoffService(get_connection()).revoke(principal, credential_id, reason)


@router.post("/receive", status_code=status.HTTP_201_CREATED)
def receive_handoff(
    payload: ReceiptReceiveRequest, principal: Principal = Depends(current_principal)
):
    service = HandoffService(get_connection())
    result = service.receive(principal, payload.model_dump())
    return result


@router.get("/batches/{batch_id}/credentials")
def list_batch_credentials(batch_id: int, principal: Principal = Depends(current_principal)):
    return HandoffService(get_connection()).list_credentials(principal, batch_id)


@router.get("/credentials/{credential_id}")
def credential_detail(credential_id: int, principal: Principal = Depends(current_principal)):
    return HandoffService(get_connection()).credential_detail(principal, credential_id)


@router.get("/batches/{batch_id}/trail")
def batch_trail(batch_id: int, principal: Principal = Depends(current_principal)):
    return HandoffService(get_connection()).batch_trail(principal, batch_id)
