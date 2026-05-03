# =============================================================================
# models.py — Pydantic request and response models
# =============================================================================

from pydantic import BaseModel, field_validator

from app.config import MAX_EMAIL_BYTES


class EmailRequest(BaseModel):
    raw_email: str

    @field_validator("raw_email")
    @classmethod
    def validate_raw_email(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("raw_email must not be empty.")
        byte_len = len(v.encode("utf-8"))
        if byte_len > MAX_EMAIL_BYTES:
            raise ValueError(
                f"Email is too large ({byte_len // 1024} KB). "
                f"Maximum allowed is {MAX_EMAIL_BYTES // 1024} KB."
            )
        return v


# ---------------------------------------------------------------------------
# Nested response models
# ---------------------------------------------------------------------------

class AuthenticationResult(BaseModel):
    spf: str
    dkim: str
    dmarc: str
    dmarc_alignment: bool


class NetworkIntelligence(BaseModel):
    origin_ip: str | None
    abuse_score: int
    isp: str


class AttachmentInfo(BaseModel):
    name: str
    sha256: str


class PayloadResult(BaseModel):
    attachments_found: list[AttachmentInfo]
    url_count: int
    urls_extracted: list[str]


class SecurityScore(BaseModel):
    score: int
    label: str
    confidence: str
    warnings: list[str]


class AnalysisResponse(BaseModel):
    request_id: str
    analysis_target: str
    subject: str
    authentication: AuthenticationResult
    network_intelligence: NetworkIntelligence
    payload: PayloadResult
    security_score: SecurityScore
