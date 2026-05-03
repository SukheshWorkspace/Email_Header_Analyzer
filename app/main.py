# =============================================================================
# main.py — FastAPI application entry point
# Pro Email Analyzer API  v9.0.0
# =============================================================================

import asyncio
import ipaddress
import uuid
from email import message_from_string
from email.utils import parseaddr

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.auth_checks import (
    async_check_spf,
    async_get_dmarc,
    async_verify_dkim,
    check_dmarc_alignment,
    extract_dkim_domain,
    extract_helo_from_received,
)
from app.config import API_TOKEN, IP_REGEX, TRUSTED_ORIGINS, logger
from app.heuristics import decode_mime_header, detect_advanced_spoof, extract_payload_data
from app.intel import async_check_abuse_db
from app.models import (
    AnalysisResponse,
    AuthenticationResult,
    EmailRequest,
    NetworkIntelligence,
    PayloadResult,
    SecurityScore,
)
from app.scoring import RiskAccumulator, score_authentication, score_network

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

def get_real_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


limiter = Limiter(key_func=get_real_ip)

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Pro Email Analyzer API",
    version="9.0.0",
    docs_url="/docs",
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=TRUSTED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_security_scheme = HTTPBearer(auto_error=False)


async def verify_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_security_scheme),
) -> None:
    if not API_TOKEN:
        logger.warning("API_TOKEN not set — running without authentication")
        return
    if credentials is None or credentials.credentials != API_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid or missing API token.")


# ---------------------------------------------------------------------------
# Async stub
# ---------------------------------------------------------------------------

async def _static(value):
    return value


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Returns the exact Pydantic validation errors as JSON so the frontend
    can display a meaningful message instead of a generic 422.
    Also logs them server-side for debugging.
    """
    errors = exc.errors()
    logger.warning("Request validation failed: %s", errors)
    # Build a human-readable message
    messages = []
    for err in errors:
        field = " -> ".join(str(loc) for loc in err.get("loc", []))
        messages.append(f"{field}: {err.get('msg', 'invalid')}")
    return JSONResponse(
        status_code=422,
        content={"detail": " | ".join(messages)},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Check server logs."},
    )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Meta"])
async def health() -> dict:
    return {"status": "ok", "version": app.version}


# ---------------------------------------------------------------------------
# Main analysis endpoint
# ---------------------------------------------------------------------------

@app.post("/analyze", response_model=AnalysisResponse, tags=["Analysis"])
@limiter.limit("20/minute")
async def analyze_email(
    request: Request,
    data: EmailRequest,
    _: None = Depends(verify_token),
) -> AnalysisResponse:
    request_id = str(uuid.uuid4())

    msg        = message_from_string(data.raw_email)
    raw_bytes  = data.raw_email.encode("utf-8", errors="ignore")

    from_addr    = parseaddr(msg.get("From", ""))[1].lower().strip()
    subject      = decode_mime_header(msg.get("Subject"), fallback="(no subject)")
    domain       = from_addr.split("@")[-1] if "@" in from_addr else ""
    envelope_from = parseaddr(msg.get("Return-Path", ""))[1].lower().strip()

    # Origin IP
    origin_ip: str | None = None
    received_headers: list[str] = msg.get_all("Received") or []

    for header in reversed(received_headers):
        for ip_str in IP_REGEX.findall(header):
            try:
                parsed_ip = ipaddress.ip_address(ip_str)
                if not parsed_ip.is_private and not parsed_ip.is_loopback and not parsed_ip.is_link_local:
                    origin_ip = ip_str
                    break
            except ValueError:
                continue
        if origin_ip:
            break

    helo_domain = extract_helo_from_received(list(reversed(received_headers))) or domain
    dkim_domain = extract_dkim_domain(msg)

    # Parallel checks
    spf_task   = async_check_spf(origin_ip, from_addr, helo_domain) if origin_ip else _static("neutral")
    dmarc_task = async_get_dmarc(domain)                              if domain    else _static("missing")
    abuse_task = async_check_abuse_db(origin_ip)                      if origin_ip else _static({"score": 0, "isp": "Unknown"})
    dkim_task  = async_verify_dkim(raw_bytes)

    results = await asyncio.gather(
        spf_task, dmarc_task, abuse_task, dkim_task,
        return_exceptions=True,
    )

    spf_result, dmarc_result, abuse_intel, dkim_result = results

    if isinstance(spf_result,   Exception): spf_result   = "neutral"
    if isinstance(dmarc_result, Exception): dmarc_result = "missing"
    if isinstance(abuse_intel,  Exception): abuse_intel  = {"score": 0, "isp": "Unknown"}
    if isinstance(dkim_result,  Exception): dkim_result  = "missing"

    # DMARC alignment
    aligned = check_dmarc_alignment(
        from_domain=domain,
        spf_result=spf_result,
        envelope_from=envelope_from,
        dkim_result=dkim_result,
        dkim_domain=dkim_domain,
    )

    # Scoring
    acc = RiskAccumulator()
    score_authentication(acc, spf=spf_result, dkim=dkim_result, dmarc=dmarc_result, dmarc_aligned=aligned)

    abuse_score = int(abuse_intel.get("score", 0))
    score_network(acc, abuse_score)

    payload_risk, urls, attachments = extract_payload_data(msg, acc.warnings)
    acc.add_payload(payload_risk)

    spoof_risk = detect_advanced_spoof(msg, acc.warnings)
    acc.add_spoof(spoof_risk)

    logger.info(
        "analysis_complete",
        extra={
            "request_id": request_id,
            "sender": from_addr,
            "domain": domain,
            "origin_ip": origin_ip,
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "dmarc_aligned": aligned,
            "abuse_score": abuse_score,
            "risk_score": acc.total,
            "label": acc.label,
        },
    )

    return AnalysisResponse(
        request_id=request_id,
        analysis_target=from_addr,
        subject=subject,
        authentication=AuthenticationResult(
            spf=spf_result,
            dkim=dkim_result,
            dmarc=dmarc_result,
            dmarc_alignment=aligned,
        ),
        network_intelligence=NetworkIntelligence(
            origin_ip=origin_ip,
            abuse_score=abuse_score,
            isp=str(abuse_intel.get("isp", "Unknown")),
        ),
        payload=PayloadResult(
            attachments_found=attachments,
            url_count=len(urls),
            urls_extracted=urls[:10],
        ),
        security_score=SecurityScore(
            score=acc.total,
            label=acc.label,
            confidence=acc.confidence,
            warnings=acc.warnings,
        ),
    )
