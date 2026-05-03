# =============================================================================
# scoring.py — Risk scoring engine
# =============================================================================

from dataclasses import dataclass, field


@dataclass
class RiskAccumulator:
    """
    Tracks risk deltas from each signal source independently,
    then produces a final calibrated score.

    Using separate buckets prevents a single-source score from silently
    dominating the total before other signals are evaluated.
    """
    auth_risk: int = 0          # SPF, DKIM, DMARC
    network_risk: int = 0       # AbuseIPDB
    payload_risk: int = 0       # Attachments, URLs
    spoof_risk: int = 0         # Header anomalies
    warnings: list[str] = field(default_factory=list)

    # Per-bucket caps prevent any one source from maxing the total
    AUTH_CAP:    int = 40
    NETWORK_CAP: int = 40
    PAYLOAD_CAP: int = 50
    SPOOF_CAP:   int = 40

    def add_auth(self, delta: int) -> None:
        self.auth_risk = min(self.auth_risk + delta, self.AUTH_CAP)

    def add_network(self, delta: int) -> None:
        self.network_risk = min(self.network_risk + delta, self.NETWORK_CAP)

    def add_payload(self, delta: int) -> None:
        self.payload_risk = min(self.payload_risk + delta, self.PAYLOAD_CAP)

    def add_spoof(self, delta: int) -> None:
        self.spoof_risk = min(self.spoof_risk + delta, self.SPOOF_CAP)

    @property
    def total(self) -> int:
        raw = self.auth_risk + self.network_risk + self.payload_risk + self.spoof_risk
        return max(0, min(raw, 100))

    @property
    def label(self) -> str:
        score = self.total
        if score >= 70:
            return "DANGEROUS"
        if score >= 40:
            return "SUSPICIOUS"
        return "SAFE"

    @property
    def confidence(self) -> str:
        """
        Confidence reflects how many signals fired, not just the score magnitude.
        A score of 70 from a single DKIM failure is lower confidence than
        a score of 70 from SPF + DKIM + AbuseIPDB all firing.
        """
        signals_fired = sum([
            self.auth_risk > 0,
            self.network_risk > 0,
            self.payload_risk > 0,
            self.spoof_risk > 0,
        ])
        if signals_fired >= 3 or self.total >= 70:
            return "HIGH"
        if signals_fired >= 2 or self.total >= 40:
            return "MEDIUM"
        return "LOW"


def score_authentication(
    acc: RiskAccumulator,
    spf: str,
    dkim: str,
    dmarc: str,
    dmarc_aligned: bool,
) -> None:
    """Applies risk scores for SPF, DKIM, and DMARC results."""

    if spf == "fail":
        acc.add_auth(30)
        acc.warnings.append("SPF authentication failed (hard fail)")
    elif spf == "softfail":
        acc.add_auth(15)
        acc.warnings.append("SPF authentication soft-failed (~all)")

    if dkim == "fail":
        acc.add_auth(35)
        acc.warnings.append("DKIM signature verification failed")
    elif dkim == "timeout":
        acc.add_auth(5)
        acc.warnings.append("DKIM verification timed out — inconclusive")

    if dmarc == "missing":
        acc.add_auth(20)
        acc.warnings.append("No DMARC record found — domain is unprotected")
    elif dmarc == "none":
        acc.add_auth(10)
        acc.warnings.append("Weak DMARC policy (p=none) — no enforcement")
    elif dmarc == "present":
        acc.add_auth(5)
        acc.warnings.append("DMARC record present but policy tag is missing/malformed")

    # Alignment failure for enforcing policies (reject/quarantine)
    if dmarc in ("reject", "quarantine") and not dmarc_aligned:
        acc.add_auth(20)
        acc.warnings.append(
            f"DMARC policy is '{dmarc}' but alignment failed — spoofed organisational domain"
        )


def score_network(acc: RiskAccumulator, abuse_score: int) -> None:
    """Maps AbuseIPDB confidence score to a capped risk delta."""
    if abuse_score <= 0:
        return
    acc.warnings.append(
        f"Origin IP AbuseIPDB confidence score: {abuse_score}%"
    )
    # Linear: 100% abuse → 40 risk points (hits network cap)
    delta = int(min(40, abuse_score * 0.4))
    acc.add_network(delta)

    if abuse_score >= 75:
        acc.warnings.append("Origin IP is highly reported for abuse — treat as untrusted")
