# =============================================================================
# auth_checks.py — SPF, DKIM, DMARC async checks + alignment verification
# =============================================================================

import asyncio
import logging
import re
from email.message import Message

import dns.resolver
import dkim
import spf
import tldextract

from app.config import DNS_EXECUTOR, DMARC_CACHE, HELO_REGEX, logger

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def get_org_domain(email_or_domain: str) -> str:
    raw = email_or_domain.split("@")[-1] if "@" in email_or_domain else email_or_domain
    ext = tldextract.extract(raw)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return raw.lower()


def extract_helo_from_received(received_headers: list[str]) -> str | None:
    for header in received_headers:
        m = HELO_REGEX.search(header)
        if m:
            candidate = m.group(1).lower()
            if candidate not in {"localhost", "unknown", "[127.0.0.1]"}:
                return candidate
    return None


def extract_dkim_domain(msg: Message) -> str | None:
    sig = msg.get("DKIM-Signature", "")
    for part in sig.split(";"):
        part = part.strip()
        if part.lower().startswith("d="):
            return part[2:].strip().lower()
    return None


def check_dmarc_alignment(
    from_domain: str,
    spf_result: str,
    envelope_from: str,
    dkim_result: str,
    dkim_domain: str | None,
) -> bool:
    from_org = get_org_domain(from_domain)
    spf_aligned = (
        spf_result == "pass"
        and bool(envelope_from)
        and from_org == get_org_domain(envelope_from)
    )
    dkim_aligned = (
        dkim_result == "pass"
        and bool(dkim_domain)
        and from_org == get_org_domain(dkim_domain)
    )
    return spf_aligned or dkim_aligned


# ---------------------------------------------------------------------------
# Async check functions
# ---------------------------------------------------------------------------

async def async_check_spf(ip: str, sender: str, helo_domain: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            DNS_EXECUTOR,
            lambda: spf.check2(i=ip, s=sender, h=helo_domain),
        )
        return result[0] if result else "neutral"
    except Exception:
        logger.warning("SPF check failed", exc_info=True)
        return "neutral"


async def async_verify_dkim(raw_bytes: bytes) -> str:
    """
    Returns: pass | fail | missing | timeout

    Handles dkimpy's strict RFC 822 parser — some legitimate emails contain
    non-standard headers (e.g. 'Signed by:' added by Gmail UI) that trigger
    MessageFormatError. These are treated as unsigned, not as failures.
    """
    loop = asyncio.get_running_loop()
    try:
        is_valid = await asyncio.wait_for(
            loop.run_in_executor(DNS_EXECUTOR, dkim.verify, raw_bytes),
            timeout=4.0,
        )
        return "pass" if is_valid else "fail"

    except asyncio.TimeoutError:
        logger.warning("DKIM verification timed out")
        return "timeout"

    except dkim.MessageFormatError as exc:
        # Non-standard headers added by mail clients — not a DKIM failure
        logger.info("DKIM skipped — non-standard header: %s", exc)
        return "missing"

    except dkim.DKIMException as exc:
        logger.info("DKIM exception: %s", exc)
        return "fail"

    except Exception:
        logger.warning("DKIM unexpected error", exc_info=True)
        return "missing"


async def async_get_dmarc(domain: str) -> str:
    if not domain:
        return "missing"

    if domain in DMARC_CACHE:
        return DMARC_CACHE[domain]

    loop = asyncio.get_running_loop()
    try:
        answers = await loop.run_in_executor(
            DNS_EXECUTOR,
            lambda: dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5),
        )
        for r in answers:
            txt = r.to_text().strip('"').strip()
            if txt.lower().startswith("v=dmarc1"):
                if "p=reject" in txt:
                    result = "reject"
                elif "p=quarantine" in txt:
                    result = "quarantine"
                elif "p=none" in txt:
                    result = "none"
                else:
                    result = "present"
                DMARC_CACHE[domain] = result
                return result
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except Exception:
        logger.warning("DMARC lookup error for %s", domain, exc_info=True)

    DMARC_CACHE[domain] = "missing"
    return "missing"
