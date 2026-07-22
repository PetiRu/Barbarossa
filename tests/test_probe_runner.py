"""Tests for active probe orchestration."""

import httpx
import pytest

from barbarossa.probe.client import SecureHTTPClient
from barbarossa.probe.runner import ProbeRunner
from barbarossa.utils.rate_limit import RateLimiter


class _HeadFallbackClient(SecureHTTPClient):
    def __init__(self) -> None:
        self.get_calls: list[str] = []

    async def head(
        self, url: str, headers: dict[str, str] | None = None
    ) -> tuple[httpx.Response | None, str | None]:
        del headers
        status = 405 if httpx.URL(url).path == "/config" else 404
        request = httpx.Request("HEAD", url)
        return httpx.Response(status, request=request), None

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> tuple[httpx.Response | None, str | None]:
        del headers, allow_redirects
        self.get_calls.append(url)
        request = httpx.Request("GET", url)
        return httpx.Response(200, request=request), None


@pytest.mark.asyncio
async def test_exposed_file_probe_falls_back_to_get_after_405() -> None:
    """GET-only endpoints are detected without issuing GET after an ordinary 404."""
    limiter = RateLimiter(requests_per_second=1_000_000, max_requests=50)
    runner = ProbeRunner(limiter)
    client = _HeadFallbackClient()
    runner.client = client

    findings = [finding async for finding in runner._check_exposed_files("http://localhost:8000")]

    assert client.get_calls == ["http://localhost:8000/config"]
    assert any(
        finding.id == "EXPOSED_FILE" and finding.endpoint.endswith("/config")
        for finding in findings
        if finding.endpoint is not None
    )
