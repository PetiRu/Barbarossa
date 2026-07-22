"""Tests for safe request and redirect handling."""

import httpx
import pytest

from barbarossa.probe.client import SecureHTTPClient


@pytest.mark.asyncio
async def test_redirect_to_metadata_is_blocked_before_second_request() -> None:
    """A redirect cannot move a request to cloud metadata."""
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(
            302,
            headers={"location": "http://169.254.169.254/latest/meta-data"},
            request=request,
        )

    def resolver(url: str, allowlist: list[str]) -> tuple[str, ...]:
        del url, allowlist
        return ("93.184.216.34",)

    client = SecureHTTPClient(
        authorized_targets=["example.com"],
        resolver=resolver,
        transport_factory=lambda addresses: httpx.MockTransport(handler),
    )
    response, error = await client.get("http://example.com")

    assert response is None
    assert error is not None and "Unsafe redirect blocked" in error
    assert requests == ["http://example.com"]


@pytest.mark.asyncio
async def test_valid_same_origin_redirect_is_followed() -> None:
    """A same-origin redirect is followed within the configured limit."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/final"}, request=request)
        return httpx.Response(200, text="ok", request=request)

    client = SecureHTTPClient(
        authorized_targets=["example.com"],
        resolver=lambda url, allowlist: ("93.184.216.34",),
        transport_factory=lambda addresses: httpx.MockTransport(handler),
    )
    response, error = await client.get("http://example.com")

    assert error is None
    assert response is not None
    assert response.status_code == 200
    assert str(response.url) == "http://example.com/final"
