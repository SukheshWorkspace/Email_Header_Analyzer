# =============================================================================
# config.py — Environment, constants, compiled patterns, shared resources
# =============================================================================

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cachetools import TTLCache
from dotenv import load_dotenv
from pythonjsonlogger import jsonlogger

# ---------------------------------------------------------------------------
# Environment — try multiple locations so it works on Windows with uvicorn
# ---------------------------------------------------------------------------
def _find_and_load_dotenv() -> None:
    """
    Searches for .env in several locations in priority order:
      1. Same directory as this file's parent (project root)
      2. Current working directory (where `python run.py` was invoked)
      3. Two levels up from this file (in case of nested install)
    """
    candidates = [
        Path(__file__).resolve().parent.parent / ".env",   # project root
        Path.cwd() / ".env",                               # cwd (run.py location)
        Path(__file__).resolve().parent.parent.parent / ".env",
    ]
    for path in candidates:
        if path.exists():
            load_dotenv(dotenv_path=path, override=True)
            logging.info(f"Loaded .env from: {path}")
            return
    logging.warning(
        ".env file not found. Searched: %s",
        ", ".join(str(p) for p in candidates)
    )

_find_and_load_dotenv()

ABUSE_DB_KEY: str = os.getenv("ABUSE_DB_KEY", "")
API_TOKEN: str    = os.getenv("API_TOKEN", "")

# CORS origins — always include "null" for file:// and localhost variants
_env_origins = os.getenv(
    "TRUSTED_ORIGINS", "http://localhost:5173,http://localhost:3000"
)
TRUSTED_ORIGINS: list[str] = list({
    *_env_origins.split(","),
    "null",                   # file:// origin (opening index.html directly)
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5500",  # VS Code Live Server default
    "http://127.0.0.1:5500",
})

if not ABUSE_DB_KEY:
    logging.warning("ABUSE_DB_KEY not set — AbuseIPDB checks will be skipped.")
if not API_TOKEN:
    logging.warning("API_TOKEN not set — endpoint is unprotected.")

# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------
handler = logging.StreamHandler()
handler.setFormatter(
    jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
)
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("email_analyzer")

# ---------------------------------------------------------------------------
# Payload limits
# ---------------------------------------------------------------------------
MAX_EMAIL_BYTES: int     = 1_000_000
MAX_ATTACHMENT_BYTES: int = 5_000_000
MAX_BODY_BYTES: int      = 200_000
MAX_HEADER_LEN: int      = 500

# ---------------------------------------------------------------------------
# Forensic constants
# ---------------------------------------------------------------------------
DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".bat", ".js", ".vbs", ".scr", ".dll",
    ".ps1", ".jar", ".macro", ".hta", ".cmd", ".com",
    ".pif", ".reg", ".wsf", ".msi",
})

SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    ".ru", ".tk", ".xyz", ".top", ".pw", ".cc",
    ".su", ".ws", ".icu", ".gq", ".cf", ".ml",
})

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly",
    "t.co", "buff.ly", "is.gd", "rb.gy", "cutt.ly",
})

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------
IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

URL_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+")

IP_URL_REGEX = re.compile(
    r"https?://(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/|$)"
)

HELO_REGEX = re.compile(r"from\s+(\S+)\s*[\(\[]", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Bounded thread pool for blocking DNS / SPF / DKIM calls
# ---------------------------------------------------------------------------
DNS_EXECUTOR = ThreadPoolExecutor(max_workers=10, thread_name_prefix="dns_worker")

# ---------------------------------------------------------------------------
# In-memory TTL caches
# ---------------------------------------------------------------------------
DMARC_CACHE: TTLCache = TTLCache(maxsize=1024, ttl=300)
ABUSE_CACHE: TTLCache = TTLCache(maxsize=512,  ttl=600)
