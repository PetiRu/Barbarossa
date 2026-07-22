"""HTTP client with scope checks, safe redirects, and DNS pinning."""

import asyncio
import logging
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urljoin, urlparse

import httpcore
import httpx

from barbarossa.scope import (
    DNSResolutionError,
    resolve_target_addresses,
    validate_redirect,
)

logger = logging.getLogger(__name__)

AddressMap = dict[str, tuple[str, ...]]
Resolver = Callable[[str, list[str]], tuple[str, ...]]
TransportFactory = Callable[[AddressMap], httpx.AsyncBaseTransport]


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect to pre-validated IPs while retaining the hostname for TLS SNI."""

    def __init__(self, addresses: AddressMap) -> None:
        self._addresses = {host.lower(): values for host, values in addresses.items()}
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Connect only to addresses pinned for the requested hostname."""
        candidates = self._addresses.get(host.rstrip(".").lower(), ())
        if not candidates:
            raise httpcore.ConnectError(f"No validated address pinned for {host}")

        last_error: Exception | None = None
        for address in candidates:
            try:
                return await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # pragma: no cover - depends on network failures
                last_error = exc
        raise httpcore.ConnectError(
            f"Could not connect to validated addresses for {host}"
        ) from last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Delegate Unix socket connections; BARBAROSSA does not request them."""
        return await self._backend.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        """Delegate asynchronous sleeps to the standard backend."""
        await self._backend.sleep(seconds)


class _PinnedHTTPTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport backed by the DNS-pinned connection pool."""

    def __init__(self, addresses: AddressMap) -> None:
        super().__init__(trust_env=False, retries=0)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
            retries=0,
            network_backend=_PinnedNetworkBackend(addresses),
        )


def _default_transport_factory(addresses: AddressMap) -> httpx.AsyncBaseTransport:
    return _PinnedHTTPTransport(addresses)


class SecureHTTPClient:
    """HTTP client that never sends a request outside validated scope."""

    _REDIRECT_STATUSES = {301, 302, 303, 307, 308}

    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 3,
        authorized_targets: list[str] | None = None,
        resolver: Resolver = resolve_target_addresses,
        transport_factory: TransportFactory = _default_transport_factory,
    ) -> None:
        """Initialize the secure HTTP client."""
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.authorized_targets = authorized_targets or ["localhost", "127.0.0.1", "::1"]
        self._resolver = resolver
        self._transport_factory = transport_factory

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        allow_redirects: bool = False,
    ) -> tuple[httpx.Response | None, str | None]:
        current_url = url
        current_method = method

        try:
            for redirect_count in range(self.max_redirects + 1):
                addresses = await asyncio.to_thread(
                    self._resolver, current_url, self.authorized_targets
                )
                hostname = (urlparse(current_url).hostname or "").rstrip(".").lower()
                transport = self._transport_factory({hostname: addresses})
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=False,
                    transport=transport,
                    trust_env=False,
                ) as client:
                    response = await client.request(
                        current_method,
                        current_url,
                        headers=headers or {},
                        data=data,
                    )

                if not allow_redirects or response.status_code not in self._REDIRECT_STATUSES:
                    return response, None

                location = response.headers.get("location")
                if not location:
                    return response, None
                if redirect_count >= self.max_redirects:
                    return None, f"Maximum redirects exceeded ({self.max_redirects})"

                redirect_url = urljoin(current_url, location)
                valid, reason = validate_redirect(
                    redirect_url, current_url, self.authorized_targets
                )
                if not valid:
                    return None, f"Unsafe redirect blocked: {reason}"

                if response.status_code == 303 and current_method != "HEAD":
                    current_method = "GET"
                    data = None
                current_url = redirect_url
        except DNSResolutionError as exc:
            return None, f"Target validation failed: {exc}"
        except httpx.TimeoutException:
            return None, "Request timeout"
        except httpx.ConnectError:
            return None, "Connection failed"
        except httpx.RequestError as exc:
            return None, f"Request error: {exc}"

        return None, "Request did not complete"

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> tuple[httpx.Response | None, str | None]:
        """Make a scope-checked GET request."""
        return await self._request("GET", url, headers=headers, allow_redirects=allow_redirects)

    async def head(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response | None, str | None]:
        """Make a scope-checked HEAD request without following redirects."""
        return await self._request("HEAD", url, headers=headers)

    async def post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response | None, str | None]:
        """Make a scope-checked POST request without following redirects."""
        return await self._request("POST", url, headers=headers, data=data)

    def get_supported_methods(self, allowed_methods: str) -> list[str]:
        """Parse an Allow header into normalized methods."""
        return [method.strip().upper() for method in allowed_methods.split(",")]
