"""Utilities for secret redaction and hashing."""

import hashlib
import re

# Patterns for common secrets
SECRET_PATTERNS = {
    "AWS_KEY": r"AKIA[0-9A-Z]{16}",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----",
    "API_KEY": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?",
    "PASSWORD": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{5,})['\"]?",
    "TOKEN": r"(?i)(token|auth|authorization)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_\.]{20,})['\"]?",
}


def redact_value(value: str, visible_chars: int = 3) -> str:
    """
    Redact a value, showing only first few characters.

    Args:
        value: The value to redact
        visible_chars: How many characters to show

    Returns:
        Redacted value like "abc***" (3 chars + asterisks)
    """
    if len(value) <= visible_chars:
        return "*" * len(value)

    return value[:visible_chars] + "***"


def redact_evidence(evidence: str, max_length: int = 200) -> str:
    """
    Redact sensitive data from evidence string.

    Removes or masks:
    - API keys
    - Tokens
    - Passwords
    - Private keys

    Args:
        evidence: The evidence string to redact
        max_length: Maximum length of returned evidence

    Returns:
        Redacted evidence string
    """
    result = evidence

    # Mask API keys
    result = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA" + "*" * 16, result)

    # Mask private keys
    result = re.sub(
        r"-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----.*?-----END (?:RSA|DSA|EC) PRIVATE KEY-----",
        "[PRIVATE KEY REDACTED]",
        result,
        flags=re.DOTALL,
    )

    # Mask JWT tokens
    result = re.sub(
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[JWT REDACTED]", result
    )

    # Mask authorization headers
    result = re.sub(
        r"(?i)(authorization|x-api-key)\s*[:=]\s*([^\s,;\"']+)",
        lambda m: f"{m.group(1)}: {'*' * len(m.group(2))}",
        result,
    )

    # Mask common assignment-style secrets while retaining the field name.
    result = re.sub(
        r"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|password|passwd|pwd|token)\b"
        r"(\s*[:=]\s*['\"]?)([^\s'\";,<>]{4,})",
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        result,
    )

    # Truncate if needed
    if len(result) > max_length:
        result = result[:max_length] + "..."

    return result


def hash_sensitive_data(data: str) -> str:
    """Create a hash for comparing sensitive data without revealing it."""
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def find_secret_patterns(content: str) -> list[tuple[str, str]]:
    """
    Find potential secrets in content.

    Args:
        content: Text to search for secrets

    Returns:
        List of (pattern_name, match) tuples
    """
    findings = []

    for pattern_name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            if isinstance(match, tuple):
                findings.append((pattern_name, match[0]))
            else:
                findings.append((pattern_name, match))

    return findings
