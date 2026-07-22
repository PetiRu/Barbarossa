"""Security header checks for probes."""

from collections.abc import Generator

from barbarossa.models import Category, Confidence, Finding, Severity


def check_security_headers(
    url: str,
    headers: dict[str, str],
) -> Generator[Finding, None, None]:
    """Check for missing or weak security headers."""

    headers_lower = {k.lower(): v for k, v in headers.items()}

    # HSTS check
    if "strict-transport-security" not in headers_lower:
        yield Finding(
            id="MISSING_HSTS",
            title="Missing Strict-Transport-Security header",
            category=Category.INSECURE_TRANSPORT,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="HSTS header forces HTTPS and prevents protocol downgrade attacks.",
            evidence="Header not found",
            endpoint=url,
            recommendation='Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            references=["https://owasp.org/www-community/attacks/HSTS"],
        )

    # CSP check
    if "content-security-policy" not in headers_lower:
        yield Finding(
            id="MISSING_CSP",
            title="Missing Content-Security-Policy header",
            category=Category.INJECTION,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="CSP prevents XSS attacks by controlling which scripts can run.",
            evidence="Header not found",
            endpoint=url,
            recommendation="Implement Content-Security-Policy header",
            references=["https://owasp.org/www-community/attacks/xss/"],
        )

    # X-Content-Type-Options check
    if "x-content-type-options" not in headers_lower:
        yield Finding(
            id="MISSING_XCONTENTTYPE",
            title="Missing X-Content-Type-Options header",
            category=Category.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="X-Content-Type-Options prevents MIME type sniffing attacks.",
            evidence="Header not found",
            endpoint=url,
            recommendation="Add: X-Content-Type-Options: nosniff",
            references=["https://owasp.org/www-community/MIME_sniffing"],
        )

    # X-Frame-Options check
    if "x-frame-options" not in headers_lower:
        yield Finding(
            id="MISSING_XFRAMEOPTIONS",
            title="Missing X-Frame-Options header",
            category=Category.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="X-Frame-Options prevents clickjacking attacks.",
            evidence="Header not found",
            endpoint=url,
            recommendation="Add: X-Frame-Options: DENY or SAMEORIGIN",
            references=["https://owasp.org/www-community/attacks/Clickjacking"],
        )

    # Referrer-Policy check
    if "referrer-policy" not in headers_lower:
        yield Finding(
            id="MISSING_REFERRER_POLICY",
            title="Missing Referrer-Policy header",
            category=Category.INFORMATION_DISCLOSURE,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description="Referrer-Policy controls what referrer information is leaked.",
            evidence="Header not found",
            endpoint=url,
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            references=["https://owasp.org/www-community/attacks/Referrer_Spoofing"],
        )

    # Permissions-Policy check
    if "permissions-policy" not in headers_lower and "feature-policy" not in headers_lower:
        yield Finding(
            id="MISSING_PERMISSIONS_POLICY",
            title="Missing Permissions-Policy header",
            category=Category.MISCONFIGURATION,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description="Permissions-Policy controls browser features accessible to the page.",
            evidence="Header not found",
            endpoint=url,
            recommendation="Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
        )

    # Check CSP strength
    if "content-security-policy" in headers_lower:
        csp = headers_lower["content-security-policy"]
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            yield Finding(
                id="WEAK_CSP",
                title="Weak Content-Security-Policy with unsafe directives",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="CSP with unsafe-inline or unsafe-eval reduces XSS protection.",
                evidence="unsafe-inline or unsafe-eval found",
                endpoint=url,
                recommendation="Remove unsafe-inline and unsafe-eval from CSP",
                references=["https://owasp.org/www-community/attacks/xss/"],
            )

    # Check X-Frame-Options strength
    if "x-frame-options" in headers_lower:
        xfo = headers_lower["x-frame-options"].upper()
        if xfo not in ("DENY", "SAMEORIGIN"):
            yield Finding(
                id="WEAK_XFRAMEOPTIONS",
                title="Weak X-Frame-Options setting",
                category=Category.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description=f"X-Frame-Options value is not DENY or SAMEORIGIN: {xfo}",
                evidence=xfo,
                endpoint=url,
                recommendation="Set to DENY or SAMEORIGIN",
                references=["https://owasp.org/www-community/attacks/Clickjacking"],
            )
