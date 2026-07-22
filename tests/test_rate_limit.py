"""Tests for rate limiting."""

import pytest

from barbarossa.utils.rate_limit import RateLimiter


def test_rate_limiter_init() -> None:
    """Test rate limiter initialization."""
    limiter = RateLimiter(requests_per_second=2, max_requests=150)
    assert limiter.request_count == 0
    assert not limiter.is_exhausted()


def test_rate_limiter_increment() -> None:
    """Test incrementing request count."""
    limiter = RateLimiter(max_requests=10)
    limiter.increment_request()
    assert limiter.request_count == 1


def test_rate_limiter_exhausted() -> None:
    """Test rate limiter exhaustion."""
    limiter = RateLimiter(max_requests=5)
    limiter.request_count = 5
    assert limiter.is_exhausted()


def test_rate_limiter_errors() -> None:
    """Test error tracking."""
    limiter = RateLimiter(max_consecutive_errors=3)
    assert not limiter.has_too_many_errors()

    limiter.increment_error()
    limiter.increment_error()
    limiter.increment_error()
    assert limiter.has_too_many_errors()


def test_rate_limiter_reset_on_success() -> None:
    """Test error counter reset on successful request."""
    limiter = RateLimiter()
    limiter.increment_error()
    assert limiter.consecutive_errors == 1

    limiter.increment_request()
    assert limiter.consecutive_errors == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requests_per_second", 0),
        ("max_requests", 0),
        ("request_timeout_seconds", 0),
        ("max_redirects", 0),
        ("max_consecutive_errors", 0),
    ],
)
def test_rate_limiter_rejects_unsafe_limits(field: str, value: int) -> None:
    """Direct API use cannot create a zero-limit or divide-by-zero limiter."""
    with pytest.raises(ValueError):
        RateLimiter(**{field: value})
