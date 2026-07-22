"""Utilities for rate limiting and request management."""

import time
from dataclasses import dataclass


@dataclass
class RateLimiter:
    """Rate limiter for HTTP requests."""

    requests_per_second: float = 2.0
    max_requests: int = 150
    request_timeout_seconds: float = 10.0
    max_redirects: int = 3
    max_consecutive_errors: int = 3

    def __post_init__(self) -> None:
        """Initialize rate limiter state."""
        self.request_count = 0
        self.consecutive_errors = 0
        self.last_request_time: float | None = None

    def wait_if_needed(self) -> None:
        """Sleep if necessary to respect rate limit."""
        if self.last_request_time is None:
            self.last_request_time = time.time()
            return

        elapsed = time.time() - self.last_request_time
        required_interval = 1.0 / self.requests_per_second

        if elapsed < required_interval:
            time.sleep(required_interval - elapsed)

        self.last_request_time = time.time()

    def increment_request(self) -> None:
        """Record a successful request."""
        self.request_count += 1
        self.consecutive_errors = 0

    def increment_error(self) -> None:
        """Record a failed request."""
        self.consecutive_errors += 1

    def is_exhausted(self) -> bool:
        """Check if request limit is reached."""
        return self.request_count >= self.max_requests

    def has_too_many_errors(self) -> bool:
        """Check if too many consecutive errors."""
        return self.consecutive_errors >= self.max_consecutive_errors

    def should_stop(self) -> bool:
        """Check if scanning should stop."""
        return self.is_exhausted() or self.has_too_many_errors()
