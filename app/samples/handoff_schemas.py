from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class CredentialIssueRequest(BaseModel):
    batch_id: int = Field(gt=0)
    handoff_party: str = Field(min_length=2, max_length=100, description="交接方，例如野外队名称或编号")
    ttl_minutes: int = Field(default=120, gt=0, le=7 * 24 * 60, description="凭证有效期（分钟）")


class CredentialRevokeRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


class CredentialRotateRequest(BaseModel):
    ttl_minutes: int | None = Field(default=None, gt=0, le=7 * 24 * 60)


class ReceiptItemInput(BaseModel):
    line_no: int = Field(gt=0)
    sample_code: str = Field(min_length=1, max_length=100)
    accepted: bool
    sample_type: str | None = Field(default=None, min_length=1, max_length=100)
    quantity: float | None = Field(default=None, gt=0)
    unit: str | None = Field(default=None, max_length=20)
    reject_reason: str | None = Field(default=None, max_length=500)
    location_id: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _check_shape(self) -> "ReceiptItemInput":
        if self.accepted:
            missing = [
                name
                for name, value in (
                    ("sample_type", self.sample_type),
                    ("quantity", self.quantity),
                    ("unit", self.unit),
                    ("location_id", self.location_id),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"接收样品必须提供：{', '.join(missing)}")
            if self.quantity is not None and self.quantity <= 0:
                raise ValueError("接收样品数量必须为正数")
            if self.reject_reason:
                raise ValueError("接收样品不能填写拒收原因")
        else:
            if not self.reject_reason:
                raise ValueError("拒收样品必须填写拒收原因")
            if self.sample_type or self.quantity is not None or self.unit or self.location_id is not None:
                raise ValueError("拒收样品不能填写样品类型、数量、单位或保管位置")
        return self


class ReceiptReceiveRequest(BaseModel):
    qr_content: str = Field(min_length=8, max_length=512, description="箱体二维码原文")
    idempotency_key: str = Field(min_length=4, max_length=100)
    handoff_party: str = Field(min_length=2, max_length=100, description="扫码时核验的交接方")
    expected_count: int = Field(gt=0, le=100_000, description="本次交接随箱单据的样品数量")
    items: list[ReceiptItemInput] = Field(min_length=1, max_length=1000)
    note: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def _check_counts(self) -> "ReceiptReceiveRequest":
        line_nos = [item.line_no for item in self.items]
        if len(set(line_nos)) != len(line_nos):
            raise ValueError("明细行号不能重复")
        codes = [item.sample_code for item in self.items]
        if len(set(codes)) != len(codes):
            raise ValueError("样品编码不能重复")
        accepted = sum(1 for item in self.items if item.accepted)
        rejected = len(self.items) - accepted
        if accepted + rejected != self.expected_count:
            raise ValueError("明细条数必须与随箱样品数量一致")
        return self
