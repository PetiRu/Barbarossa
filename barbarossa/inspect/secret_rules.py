"""Secret detection rules."""

import re
from collections.abc import Generator

from barbarossa.models import Category, Confidence, Finding, Severity
from barbarossa.utils.redaction import redact_value

# Common secret patterns
PATTERNS = {
    "AWS_KEY": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "confidence": Confidence.HIGH,
    },
    "PRIVATE_KEY": {
        "pattern": r"-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----",
        "confidence": Confidence.HIGH,
    },
    "GCP_KEY": {
        "pattern": r'"type":\s*"service_account"',
        "confidence": Confidence.HIGH,
    },
    "GITHUB_TOKEN": {
        "pattern": r"github_token\s*=\s*['\"]([a-zA-Z0-9_]{36,})['\"]",
        "confidence": Confidence.MEDIUM,
    },
    "API_KEY": {
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?",
        "confidence": Confidence.MEDIUM,
    },
    "PASSWORD_LITERAL": {
        "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^\s'\"]{5,})['\"]",
        "confidence": Confidence.MEDIUM,
    },
    "DATABASE_URL": {
        "pattern": r"(?i)(database|db)_?url\s*[:=]\s*['\"]?([a-zA-Z]+://[^\s'\"]+)['\"]?",
        "confidence": Confidence.MEDIUM,
    },
}


def detect_secrets(file_path: str, content: str, max_lines: int = 1000) -> Generator[Finding, None, None]:
    """Detect hardcoded secrets in file content."""

    # Skip large files
    lines = content.split("\n")
    if len(lines) > max_lines:
        return

    for pattern_name, config in PATTERNS.items():
        pattern = config["pattern"]
        confidence = config["confidence"]

        for match_obj in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            # Get line number
            line_num = content[:match_obj.start()].count("\n") + 1

            # Get the matched text
            matched = match_obj.group(0)
            redacted = redact_value(matched)

            yield Finding(
                id=f"SECRET_{pattern_name}",
                title=f"Hardcoded secret: {pattern_name}",
                category=Category.SECRETS,
                severity=Severity.CRITICAL,
                confidence=Confidence(confidence),
                description=f"Potential {pattern_name} detected in source code.",
                evidence=redacted,
                file_path=file_path,
                line_number=line_num,
                recommendation="Remove this secret from the source code. Use environment variables or secure secret management instead.",
                references=["https://owasp.org/www-community/Sensitive_Data_Exposure"],
            )


def detect_weak_crypto(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Detect weak cryptographic practices."""

    weak_crypto_patterns = {
        "MD5": (r"md5\(", r"hashlib\.md5"),
        "SHA1": (r"sha1\(", r"hashlib\.sha1"),
        "DES": (r"DES\.new", r"DES3\.new"),
    }

    for crypto_name, patterns in weak_crypto_patterns.items():
        for pattern in patterns:
            for match_obj in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match_obj.start()].count("\n") + 1

                yield Finding(
                    id=f"WEAK_CRYPTO_{crypto_name}",
                    title=f"Weak cryptography: {crypto_name}",
                    category=Category.WEAK_CRYPTO,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=f"{crypto_name} is considered cryptographically weak and should not be used for security-sensitive operations.",
                    evidence=pattern,
                    file_path=file_path,
                    line_number=line_num,
                    recommendation=f"Use SHA-256 or stronger algorithms instead of {crypto_name}.",
                    references=["https://owasp.org/www-community/Weak_Cryptography"],
                )


def detect_debug_mode(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Detect debug mode enabled in production."""

    debug_patterns = {
        "FLASK_DEBUG": r"(?i)debug\s*=\s*True",
        "DJANGO_DEBUG": r"DEBUG\s*=\s*True",
        "CONSOLE_LOG": r"console\.log\(",
        "PRINT_STATEMENTS": r"print\(",
    }

    for pattern_name, pattern in debug_patterns.items():
        for match_obj in re.finditer(pattern, content):
            line_num = content[:match_obj.start()].count("\n") + 1

            yield Finding(
                id=f"DEBUG_{pattern_name}",
                title=f"Debug mode enabled: {pattern_name}",
                category=Category.INFORMATION_DISCLOSURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description="Debug mode is enabled, which may expose sensitive information.",
                evidence=match_obj.group(0),
                file_path=file_path,
                line_number=line_num,
                recommendation="Disable debug mode in production configurations.",
                references=["https://owasp.org/www-community/Exposure_of_Sensitive_Information_to_an_Unauthorized_Actor"],
            )
