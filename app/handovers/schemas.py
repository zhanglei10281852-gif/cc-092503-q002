from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class CredentialIssue(BaseModel):
    batch_id: int = Field(gt=0)
    from_party: str = Field(min_length=1, max_length=100, description="交出方，如野外队编号或名称")
    from_party_contact: str = Field(default="", max_length=100)
    to_party: str = Field(default="", max_length=100, description="预期接收方；留空表示不校验扫码接收人")
    ttl_minutes: int = Field(default=120, ge=1, le=7 * 24 * 60)


class CredentialRotate(BaseModel):
    to_party: str | None = Field(default=None, max_length=100)
    ttl_minutes: int | None = Field(default=None, ge=1, le=7 * 24 * 60)


class CredentialRevoke(BaseModel):
    reason: str = Field(default="", max_length=500)


class RejectReason(BaseModel):
    sample_code: str = Field(default="", max_length=100)
    reason: str = Field(min_length=1, max_length=500)


class HandoverReceive(BaseModel):
    credential: str = Field(min_length=8, max_length=512, description="扫码得到的二维码明文")
    expected_count: int = Field(gt=0)
    accepted_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    reject_reasons: list[RejectReason] = Field(default_factory=list, max_length=1000)
    location_id: int = Field(gt=0)
    custodian_user_id: int | None = Field(default=None, gt=0)
    note: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _check_counts(self):
        if self.accepted_count + self.rejected_count != self.expected_count:
            raise ValueError("接收数量与拒收数量之和必须等于本次交接数量")
        if self.rejected_count > 0 and not self.reject_reasons:
            raise ValueError("存在拒收样品时必须填写拒收原因")
        return self
