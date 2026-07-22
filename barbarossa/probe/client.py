"""HTTP client for probes."""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SecureHTTPClient:
    """HTTP client with security checks."""

    def __init__(self, timeout: float = 10.0, max_redirects: int = 3) -> None:
        """Initialize HTTP client."""
        self.timeout = timeout
        self.max_redirects = max_redirects

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> tuple[httpx.Response | None, str | None]:
        """
        Make GET request.

        Returns (response, error_message)
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=allow_redirects,
            ) as client:
                response = await client.get(url, headers=headers or {})
                return response, None
        except httpx.TimeoutException:
            return None, "Request timeout"
        except httpx.ConnectError:
            return None, "Connection failed"
        except Exception as e:
            return None, f"Request error: {e}"

    async def head(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response | None, str | None]:
        """Make HEAD request."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.head(url, headers=headers or {}, follow_redirects=False)
                return response, None
        except Exception as e:
            return None, f"HEAD request error: {e}"

    async def post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response | None, str | None]:
        """Make POST request."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, data=data, headers=headers or {}, follow_redirects=False)
                return response, None
        except Exception as e:
            return None, f"POST request error: {e}"

    def get_supported_methods(self, allowed_methods: str) -> list[str]:
        """Parse allowed methods from header."""
        return [m.strip() for m in allowed_methods.split(",")]
