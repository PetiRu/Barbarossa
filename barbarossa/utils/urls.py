"""URL and hostname utilities."""

from urllib.parse import urljoin, urlparse


def extract_hostname(url: str) -> str:
    """Extract hostname from URL."""
    parsed = urlparse(url)
    return parsed.hostname or ""


def extract_port(url: str) -> int:
    """Extract port from URL, defaulting to 80/443."""
    parsed = urlparse(url)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def normalize_url(url: str) -> str:
    """Normalize URL for comparison."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def is_absolute_url(url: str) -> bool:
    """Check if URL is absolute."""
    return url.startswith(("http://", "https://", "//"))


def build_absolute_url(base_url: str, relative_url: str) -> str:
    """Build absolute URL from base and relative."""
    if is_absolute_url(relative_url):
        return relative_url
    return urljoin(base_url, relative_url)


def extract_endpoints(url: str) -> list[str]:
    """Extract common endpoints to test from a base URL."""
    endpoints = []
    base = url.rstrip("/")

    common = [
        "/",
        "/api",
        "/admin",
        "/login",
        "/logout",
        "/register",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/debug",
        "/config",
        "/.env",
        "/.git/config",
        "/server-status",
        "/health",
        "/status",
    ]

    for endpoint in common:
        endpoints.append(base + endpoint)

    return endpoints


def sanitize_url_for_display(url: str) -> str:
    """Sanitize URL for display in reports."""
    if not url:
        return ""

    # Limit length
    max_len = 200
    if len(url) > max_len:
        return url[:max_len] + "..."

    return url
