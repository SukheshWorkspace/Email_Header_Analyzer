# =============================================================================
# heuristics.py — Payload extraction, URL analysis, and spoof detection
# =============================================================================

import hashlib
import unicodedata
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr
from urllib.parse import urlparse

from app.config import (
    DANGEROUS_EXTENSIONS,
    IP_URL_REGEX,
    MAX_ATTACHMENT_BYTES,
    MAX_BODY_BYTES,
    MAX_HEADER_LEN,
    SUSPICIOUS_TLDS,
    URL_REGEX,
    URL_SHORTENERS,
    logger,
)
from app.models import AttachmentInfo


# ---------------------------------------------------------------------------
# Header sanitization
# ---------------------------------------------------------------------------

def safe_header(raw: str, max_len: int = MAX_HEADER_LEN) -> str:
    """
    Strips control characters (category C*) from a decoded header value
    and truncates to max_len to prevent output injection or oversized fields.
    """
    cleaned = "".join(
        ch for ch in raw if unicodedata.category(ch)[0] != "C"
    )
    return cleaned[:max_len]


def decode_mime_header(raw_value: str | None, fallback: str = "") -> str:
    """Decodes an RFC 2047-encoded MIME header safely, with sanitization."""
    if not raw_value:
        return fallback
    try:
        decoded = str(make_header(decode_header(raw_value)))
        return safe_header(decoded)
    except Exception:
        return safe_header(raw_value)


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------

def analyze_url(url: str, warnings: list[str]) -> int:
    """
    Evaluates a single URL for phishing indicators.
    Returns a risk delta (int).
    """
    risk = 0
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return 0

    if not hostname:
        return 0

    # TLD check against parsed hostname (not raw URL string)
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        warnings.append(f"Suspicious TLD in URL: {url[:120]}")
        risk += 15

    # URL shortener detection via hostname
    if any(shortener in hostname for shortener in URL_SHORTENERS):
        warnings.append(f"URL shortener detected: {url[:120]}")
        risk += 10

    # IP-based URL (direct IP used as host — strong phishing indicator)
    if IP_URL_REGEX.search(url):
        warnings.append(f"IP-based URL (phishing risk): {url[:120]}")
        risk += 20

    # Punycode / homograph domain
    if "xn--" in hostname:
        warnings.append(f"Punycode domain detected (possible homograph): {hostname}")
        risk += 15

    # HTTP (not HTTPS) links in body
    if url.startswith("http://"):
        warnings.append(f"Unencrypted HTTP link: {url[:120]}")
        risk += 5

    return risk


# ---------------------------------------------------------------------------
# Payload extraction
# ---------------------------------------------------------------------------

def extract_payload_data(
    msg: Message, warnings: list[str]
) -> tuple[int, list[str], list[AttachmentInfo]]:
    """
    Walks all MIME parts to:
      - Hash and risk-score attachments
      - Extract URLs from text/plain and text/html bodies
      - Apply URL-level heuristics

    Returns (risk_delta, urls, attachments).
    """
    risk = 0
    urls: set[str] = set()
    attachments: list[AttachmentInfo] = []

    for part in msg.walk():
        content_disposition = part.get_content_disposition() or ""
        filename = part.get_filename()

        # --- Attachment handling ---
        if filename:
            decoded_name = decode_mime_header(filename, fallback="unnamed_attachment")

            try:
                payload_bytes = part.get_payload(decode=True)

                if payload_bytes is None:
                    continue

                if len(payload_bytes) > MAX_ATTACHMENT_BYTES:
                    warnings.append(
                        f"Oversized attachment skipped ({len(payload_bytes) // 1024} KB): {decoded_name}"
                    )
                    risk += 5
                    continue

                file_hash = hashlib.sha256(payload_bytes).hexdigest()
                attachments.append(AttachmentInfo(name=decoded_name, sha256=file_hash))

                # Dangerous extension check
                lower_name = decoded_name.lower()
                if any(lower_name.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                    warnings.append(f"Dangerous attachment extension: {decoded_name}")
                    risk += 60

                # Double-extension trick (e.g. invoice.pdf.exe)
                parts = lower_name.rsplit(".", 2)
                if len(parts) == 3 and f".{parts[-1]}" in DANGEROUS_EXTENSIONS:
                    warnings.append(f"Double-extension trick detected: {decoded_name}")
                    risk += 20

            except Exception:
                logger.warning("Attachment processing error for: %s", decoded_name, exc_info=True)
                continue

        # --- Body URL extraction ---
        content_type = part.get_content_type()
        if content_type in ("text/plain", "text/html"):
            try:
                raw_bytes = part.get_payload(decode=True)
                if raw_bytes is None:
                    continue

                # Cap body size before URL extraction
                if len(raw_bytes) > MAX_BODY_BYTES:
                    warnings.append(
                        f"Body truncated at {MAX_BODY_BYTES // 1024} KB for URL extraction."
                    )
                    raw_bytes = raw_bytes[:MAX_BODY_BYTES]

                body = raw_bytes.decode("utf-8", errors="ignore")
                found = URL_REGEX.findall(body)
                urls.update(found)

            except Exception:
                logger.warning("Body parsing error", exc_info=True)

    # --- URL-level heuristics ---
    url_risk = sum(analyze_url(u, warnings) for u in urls)
    risk += url_risk

    if len(urls) > 15:
        warnings.append(f"High URL volume in body: {len(urls)} links")
        risk += 10

    return risk, sorted(urls), attachments


# ---------------------------------------------------------------------------
# Spoof detection
# ---------------------------------------------------------------------------

def detect_advanced_spoof(msg: Message, warnings: list[str]) -> int:
    """
    Detects display-name spoofing, Reply-To mismatches, and forged
    Authentication-Results headers.
    Returns a risk delta (int).
    """
    risk = 0
    from_raw = msg.get("From", "")
    from_name, from_email = parseaddr(from_raw)

    # Missing or malformed From address
    if not from_email or "@" not in from_email:
        warnings.append("Missing or malformed From address — high spoofing risk")
        risk += 40
        return risk

    # Reply-To mismatch
    reply_raw = msg.get("Reply-To", "")
    _, reply_email = parseaddr(reply_raw)
    if reply_email and reply_email.lower() != from_email.lower():
        warnings.append(
            f"Reply-To mismatch: replies go to {reply_email!r}, not sender {from_email!r}"
        )
        risk += 25

    # Email address hidden inside the display name
    if "@" in from_name and from_name.strip().lower() != from_email.lower():
        warnings.append(
            "Email address hidden in display name (display-name spoofing)"
        )
        risk += 40

    # Multiple Authentication-Results headers (injected by relay or forged)
    auth_results = msg.get_all("Authentication-Results", [])
    if len(auth_results) > 1:
        warnings.append(
            f"Multiple Authentication-Results headers ({len(auth_results)}) — possible forgery"
        )
        risk += 30

    # From / Envelope-From domain mismatch (available if Received headers present)
    return_path_raw = msg.get("Return-Path", "")
    _, return_path_email = parseaddr(return_path_raw)
    if return_path_email and "@" in return_path_email:
        from_domain = from_email.split("@")[-1].lower()
        rp_domain = return_path_email.split("@")[-1].lower()
        if from_domain != rp_domain:
            warnings.append(
                f"From domain ({from_domain}) differs from Return-Path domain ({rp_domain})"
            )
            risk += 20

    return risk
