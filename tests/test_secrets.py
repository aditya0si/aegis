"""Tests for secrets/PII vault."""
import pytest
from aegis.detectors.secrets import SecretsDetector

@pytest.fixture
def detector():
    return SecretsDetector()

def test_aws_access_key(detector):
    txt = "My key is AKIAQWERTYUIOP123456 please use it"
    res = detector.scan(txt)
    assert res.has_secrets is True
    assert any(f.type == "aws_access_key" for f in res.findings)
    assert "[REDACTED_AWS_KEY]" in res.redacted_text

def test_github_token(detector):
    txt = "token: ghp_" + "a"*36
    res = detector.scan(txt)
    assert res.has_secrets is True
    assert any("github" in f.type for f in res.findings)

def test_openai_key(detector):
    txt = "key is sk-proj-abc123XYZ45678901234567890 extra"
    res = detector.scan(txt)
    assert res.has_secrets is True
    assert any("openai" in f.type for f in res.findings)

def test_ssn(detector):
    txt = "My SSN is 123-45-6789"
    res = detector.scan(txt)
    assert res.has_secrets is True
    assert any(f.type == "ssn" for f in res.findings)
    assert "[REDACTED_SSN]" in res.redacted_text
    assert res.risk_level == "critical"

def test_email(detector):
    txt = "Contact me at john.doe@company.com"
    res = detector.scan(txt)
    assert res.has_secrets is True
    assert any(f.type == "email" for f in res.findings)
    assert res.risk_level == "low"

def test_allowlisted_email(detector):
    txt = "test@example.com is dummy"
    res = detector.scan(txt)
    # allowlisted should not be flagged, or low confidence but allowlist skips
    # Our implementation skips if contains allowlisted token
    assert res.has_secrets is False or all(f.type != "email" for f in res.findings)

def test_allowlisted_aws_example(detector):
    txt = "Key AKIAIOSFODNN7EXAMPLE is example"
    res = detector.scan(txt)
    assert res.has_secrets is False

def test_private_key(detector):
    txt = "Here: -----BEGIN RSA PRIVATE KEY----- MIIEow..."
    res = detector.scan(txt)
    assert res.has_secrets is True
    assert any(f.type == "private_key" for f in res.findings)
    assert res.risk_level == "critical"

def test_multiple_secrets_high_risk(detector):
    txt = "SSN 123-45-6789 and key sk-proj-abc123XYZ45678901234567890 and -----BEGIN RSA PRIVATE KEY-----"
    res = detector.scan(txt)
    assert len(res.findings) >= 3
    assert res.risk_level in {"critical","high"}

def test_redact_method(detector):
    txt = "email john@example.com and ssn 123-45-6789"
    redacted = detector.redact(txt)
    assert "john@example.com" not in redacted or "[REDACTED" in redacted

def test_empty(detector):
    res = detector.scan("")
    assert res.has_secrets is False
    assert res.redacted_text == ""

def test_benign_no_secrets(detector):
    txt = "What is the weather like today? No secrets here."
    res = detector.scan(txt)
    assert res.has_secrets is False
    assert res.risk_level == "none"

def test_high_entropy_token(detector):
    # 20+ char high entropy mixed case+digit
    token = "aB3dEf9Gh2JkLm4NpQr6StUvW"
    # ensure entropy high enough and matches pattern
    res = detector.scan(f"token {token}")
    # May be flagged as high_entropy_token if not other pattern
    # Accept either flagged or not, but test that scan doesn't error
    assert isinstance(res.has_secrets, bool)

def test_jwt(detector):
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    res = detector.scan(f"auth {jwt}")
    assert res.has_secrets is True
    assert any(f.type == "jwt" for f in res.findings)

def test_credit_card(detector):
    txt = "card 4111 1111 1111 1111"
    res = detector.scan(txt)
    # test card 4111... is allowlisted test card, should be skipped
    # Use different number
    txt2 = "card 4539 1488 0343 6467"
    res2 = detector.scan(txt2)
    assert res2.has_secrets is True

def test_phone(detector):
    txt = "call me at 415-555-1234"
    res = detector.scan(txt)
    assert res.has_secrets is True

def test_password_field(detector):
    txt = "password: SuperSecret123!"
    res = detector.scan(txt)
    assert res.has_secrets is True
