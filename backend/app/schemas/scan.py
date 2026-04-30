from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator


class ScanCreate(BaseModel):
    target_url: HttpUrl
    profile: str = Field(default="quick", pattern="^(quick|full|custom)$")
    authorization_confirmed: bool = Field(
        ...,
        description="Must be true to confirm written authorization for target testing.",
    )
    in_scope_urls: list[HttpUrl] = Field(default_factory=list)
    exclusions: list[str] = Field(
        default_factory=list,
        description="Path patterns or URL fragments to exclude from scanning.",
    )

    @field_validator("authorization_confirmed")
    @classmethod
    def ensure_authorization(cls, value: bool) -> bool:
        if not value:
            raise ValueError("You must confirm authorization before submitting a scan.")
        return value


class ScanRead(BaseModel):
    id: int
    target_url: str
    profile: str
    status: str
    authorization_confirmed: bool
    in_scope_urls: list[str]
    exclusions: list[str]
    findings_json: str | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class Finding(BaseModel):
    module: str
    title: str
    severity: str
    description: str
    evidence: dict[str, Any] = {}
    remediation: str
