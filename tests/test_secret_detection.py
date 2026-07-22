"""Tests for secret detection."""

from barbarossa.inspect.secret_rules import detect_debug_mode, detect_secrets, detect_weak_crypto


def test_detect_aws_key() -> None:
    """Test AWS key detection."""
    content = "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
    findings = list(detect_secrets("test.py", content))
    assert any(f.id == "SECRET_AWS_KEY" for f in findings)


def test_detect_private_key() -> None:
    """Test private key detection."""
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    findings = list(detect_secrets("test.py", content))
    assert any(f.id == "SECRET_PRIVATE_KEY" for f in findings)


def test_detect_api_key() -> None:
    """Test API key detection."""
    content = "api_key = 'sk_live_abcdefghijklmnopqrst'"
    findings = list(detect_secrets("test.py", content))
    assert any(f.id == "SECRET_API_KEY" for f in findings)


def test_detect_md5() -> None:
    """Test MD5 weak crypto detection."""
    content = "import hashlib\nhash = hashlib.md5(password.encode())"
    findings = list(detect_weak_crypto("test.py", content))
    assert any("MD5" in f.id for f in findings)


def test_detect_debug_mode() -> None:
    """Test debug mode detection."""
    content = "DEBUG = True"
    findings = list(detect_debug_mode("settings.py", content))
    assert any("DEBUG_" in f.id for f in findings)


def test_no_secrets_in_safe_code() -> None:
    """Test safe code without secrets."""
    content = """
api_key_env = os.environ.get('API_KEY')
password = input("Enter password: ")
"""
    findings = list(detect_secrets("test.py", content))
    # Should not detect env var references or input()
    assert len([f for f in findings if f.category.value == "SECRETS"]) == 0
