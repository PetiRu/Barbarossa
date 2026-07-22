"""Probe runner for active security checks."""

import logging
from collections.abc import AsyncGenerator

from barbarossa.models import Category, Confidence, Finding, Severity
from barbarossa.probe.client import SecureHTTPClient
from barbarossa.probe.headers import check_security_headers
from barbarossa.utils.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


class ProbeRunner:
    """Run active HTTP security probes."""

    def __init__(self, rate_limiter: RateLimiter) -> None:
        """Initialize probe runner."""
        self.rate_limiter = rate_limiter
        self.client = SecureHTTPClient(
            timeout=rate_limiter.request_timeout_seconds,
            max_redirects=rate_limiter.max_redirects,
        )
        self.findings: list[Finding] = []

    async def probe_url(self, url: str) -> AsyncGenerator[Finding, None]:
        """Run all probes on a URL."""
        if self.rate_limiter.should_stop():
            return

        # Check HTTPS availability
        async for finding in self._check_https_redirect(url):
            yield finding

        # Check security headers
        async for finding in self._check_headers(url):
            yield finding

        # Check common exposed files
        async for finding in self._check_exposed_files(url):
            yield finding

        # Check for directory listing
        async for finding in self._check_directory_listing(url):
            yield finding

    async def _check_https_redirect(self, url: str) -> AsyncGenerator[Finding, None]:
        """Check for HTTPS and HTTP to HTTPS redirect."""
        if not url.startswith("http://"):
            return

        https_url = url.replace("http://", "https://", 1)

        self.rate_limiter.wait_if_needed()
        response, error = await self.client.head(https_url)
        self.rate_limiter.increment_request()

        if response and response.status_code < 400:
            # HTTPS is available
            pass
        else:
            yield Finding(
                id="NO_HTTPS",
                title="HTTPS not available",
                category=Category.INSECURE_TRANSPORT,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="The target does not support HTTPS.",
                evidence="HTTPS connection failed",
                endpoint=https_url,
                recommendation="Enable HTTPS/TLS for your application",
                references=["https://owasp.org/www-community/attacks/man-in-the-middle"],
            )

    async def _check_headers(self, url: str) -> AsyncGenerator[Finding, None]:
        """Check security headers on response."""
        self.rate_limiter.wait_if_needed()
        response, error = await self.client.get(url)
        self.rate_limiter.increment_request()

        if error:
            logger.debug(f"Error getting headers from {url}: {error}")
            return

        if response:
            for finding in check_security_headers(url, dict(response.headers)):
                yield finding

    async def _check_exposed_files(self, url: str) -> AsyncGenerator[Finding, None]:
        """Check for commonly exposed files."""
        exposed_files = [
            "/.git/config",
            "/.env",
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
            "/debug",
            "/admin",
        ]

        base_url = url.rstrip("/")

        for file_path in exposed_files:
            if self.rate_limiter.should_stop():
                break

            test_url = base_url + file_path
            self.rate_limiter.wait_if_needed()
            response, error = await self.client.head(test_url)
            self.rate_limiter.increment_request()

            if response and response.status_code == 200:
                yield Finding(
                    id="EXPOSED_FILE",
                    title=f"Exposed file found: {file_path}",
                    category=Category.INFORMATION_DISCLOSURE,
                    severity=Severity.MEDIUM if ".git" in file_path or ".env" in file_path else Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=f"File {file_path} is publicly accessible.",
                    evidence=test_url,
                    endpoint=test_url,
                    recommendation=f"Restrict access to {file_path} or remove it from public directory.",
                    references=["https://owasp.org/www-community/Sensitive_Data_Exposure"],
                )

    async def _check_directory_listing(self, url: str) -> AsyncGenerator[Finding, None]:
        """Check if directory listing is enabled."""
        self.rate_limiter.wait_if_needed()
        response, error = await self.client.get(url)
        self.rate_limiter.increment_request()

        if response and response.text:
            # Simple heuristics for directory listing
            if any(indicator in response.text for indicator in [
                "<Directory>",
                "Index of /",
                "Parent Directory",
                "[PARENTDIR]",
            ]):
                yield Finding(
                    id="DIRECTORY_LISTING",
                    title="Directory listing is enabled",
                    category=Category.INFORMATION_DISCLOSURE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description="Web server allows browsing directory contents.",
                    evidence="Directory listing HTML detected",
                    endpoint=url,
                    recommendation="Disable directory listing in web server configuration.",
                    references=["https://owasp.org/www-community/Sensitive_Data_Exposure"],
                )

    async def run_probes(self, url: str) -> list[Finding]:
        """Run all probes and return findings."""
        self.findings = []

        async for finding in self.probe_url(url):
            self.findings.append(finding)
            if self.rate_limiter.should_stop():
                break

        return self.findings
