"""Secrets & PII Vault — regex + entropy + allowlist."""
from __future__ import annotations

import math
import re
from collections import Counter

from pydantic import BaseModel, Field

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]"),
    ("aws_secret_key", r"\b[A-Za-z0-9/+=]{40}\b", "[REDACTED_AWS_SECRET]"),
    ("github_token", r"\bghp_[A-Za-z0-9]{36}\b", "[REDACTED_GITHUB_TOKEN]"),
    ("github_token2", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", "[REDACTED_GITHUB_TOKEN]"),
    ("openai_key", r"\bsk-(proj-)?[A-Za-z0-9]{20,}\b", "[REDACTED_OPENAI_KEY]"),
    ("stripe_key", r"\bsk_(live|test)_[A-Za-z0-9]{20,}\b", "[REDACTED_STRIPE_KEY]"),
    ("slack_token", r"\bxox[bpras]-[A-Za-z0-9-]{10,}\b", "[REDACTED_SLACK_TOKEN]"),
    ("private_key", r"-----BEGIN (RSA )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    ("google_api", r"\bAIza[0-9A-Za-z-_]{35}\b", "[REDACTED_GOOGLE_API_KEY]"),
    ("generic_api_key", r"\bapi[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9-_]{20,}['\"]?", "[REDACTED_API_KEY]"),
    ("password_field", r"\bpassword\s*[:=]\s*['\"]?[^\s'\"]{6,}", "[REDACTED_PASSWORD]"),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    ("credit_card", r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED_CC]"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
    ("phone_us", r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[REDACTED_PHONE]"),
    ("jwt", r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "[REDACTED_JWT]"),
]

ALLOWLIST_TOKENS = {
    "test@example.com",
    "example@example.com",
    "000-00-0000",
    "AKIAIOSFODNN7EXAMPLE",
    "sk-test-fake-key-for-unit-tests-123",
}

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

class SecretFinding(BaseModel):
    type: str
    match: str
    redacted: str
    start: int
    end: int
    confidence: float
    entropy: float | None = None

class ScanResult(BaseModel):
    has_secrets: bool
    findings: list[SecretFinding] = Field(default_factory=list)
    redacted_text: str = ""
    risk_level: str = "none"

class SecretsDetector:
    def __init__(self, allowlist: set[str] | None = None, entropy_threshold: float = 4.2):
        self.allowlist = allowlist or ALLOWLIST_TOKENS
        self.entropy_threshold = entropy_threshold
        self._compiled = [(name, re.compile(pat, re.IGNORECASE), repl) for name, pat, repl in SECRET_PATTERNS]

    def _is_allowlisted(self, match: str) -> bool:
        m = match.strip("'\" ")
        if m in self.allowlist:
            return True
        for tok in self.allowlist:
            if tok in m:
                return True
        if m.lower() in {"test","example","placeholder","fake","dummy"}:
            return True
        return False

    def scan(self, text: str) -> ScanResult:
        if not text:
            return ScanResult(has_secrets=False, findings=[], redacted_text=text, risk_level="none")
        findings: list[SecretFinding] = []
        for name, pat, repl in self._compiled:
            for m in pat.finditer(text):
                raw = m.group(0)
                if self._is_allowlisted(raw):
                    continue
                if name in {"aws_secret_key","generic_api_key","credit_card","phone_us"}:
                    if name == "credit_card":
                        digits = re.sub(r"\D", "", raw)
                        if not (13 <= len(digits) <= 16):
                            continue
                        if digits in {"0000000000000000","4111111111111111"}:
                            continue
                    if name == "phone_us":
                        digits = re.sub(r"\D", "", raw)
                        if len(digits) < 10:
                            continue
                        if raw.strip().isdigit() and len(raw.strip()) == 4:
                            continue
                    if name == "aws_secret_key":
                        ent = shannon_entropy(raw)
                        if ent < self.entropy_threshold:
                            continue
                    if name == "generic_api_key":
                        ent = shannon_entropy(raw)
                        if ent < 3.8:
                            continue
                ent = shannon_entropy(raw) if len(raw) > 12 else None
                conf = 0.9 if name in {"aws_access_key","github_token","openai_key","private_key","ssn","jwt"} else 0.78
                if name == "email" and raw.endswith("@example.com"):
                    conf = 0.55
                findings.append(SecretFinding(
                    type=name,
                    match=raw,
                    redacted=repl,
                    start=m.start(),
                    end=m.end(),
                    confidence=conf,
                    entropy=round(ent,3) if ent is not None else None,
                ))
        if findings:
            findings.sort(key=lambda f: (f.start, -f.confidence))
            deduped: list[SecretFinding] = []
            last_end = -1
            for f in findings:
                if f.start >= last_end:
                    deduped.append(f)
                    last_end = f.end
                elif f.confidence > deduped[-1].confidence:
                    deduped[-1] = f
                    last_end = f.end
            findings = deduped
        redacted = text
        for f in sorted(findings, key=lambda x: x.start, reverse=True):
            redacted = redacted[:f.start] + f.redacted + redacted[f.end:]
        # high-entropy generic token
        if not any(f.type in {"aws_access_key","github_token","openai_key"} for f in findings):
            for m in re.finditer(r"\b[A-Za-z0-9-_+/=]{20,}\b", text):
                raw = m.group(0)
                if raw in self.allowlist or len(raw) < 20:
                    continue
                if any(f.start <= m.start() < f.end for f in findings):
                    continue
                ent = shannon_entropy(raw)
                if ent >= 4.6 and re.search(r"[A-Z]", raw) and re.search(r"[a-z]", raw) and re.search(r"[0-9]", raw):
                    findings.append(SecretFinding(type="high_entropy_token", match=raw, redacted="[REDACTED_HIGH_ENTROPY]", start=m.start(), end=m.end(), confidence=0.65, entropy=round(ent,3)))
                    redacted = redacted[:m.start()] + "[REDACTED_HIGH_ENTROPY]" + redacted[m.end():]
        has_secrets = len(findings) > 0
        if not has_secrets:
            risk = "none"
        elif any(f.type in {"private_key","aws_access_key","github_token","openai_key","ssn","jwt"} for f in findings):
            risk = "critical"
        elif len(findings) >= 3:
            risk = "high"
        elif any(f.type in {"credit_card","generic_api_key","aws_secret_key"} for f in findings):
            risk = "high"
        elif any(f.type in {"email","phone_us"} for f in findings) and len(findings) == 1:
            risk = "low"
        else:
            risk = "medium"
        return ScanResult(has_secrets=has_secrets, findings=findings, redacted_text=redacted, risk_level=risk)

    def redact(self, text: str) -> str:
        return self.scan(text).redacted_text
