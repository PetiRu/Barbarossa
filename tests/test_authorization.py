"""Tests for authorization."""

import os
from barbarossa.authorization import get_authorization_from_env, check_authorization


def test_env_auth_enabled(monkeypatch) -> None:  # type: ignore
    """Test authorization from environment."""
    monkeypatch.setenv("BARBAROSSA_AUTHORIZED", "true")
    assert get_authorization_from_env()


def test_env_auth_disabled() -> None:
    """Test authorization from environment when not set."""
    # Make sure env var is not set
    if "BARBAROSSA_AUTHORIZED" in os.environ:
        del os.environ["BARBAROSSA_AUTHORIZED"]
    assert not get_authorization_from_env()


def test_check_authorization_explicit() -> None:
    """Test explicit authorization."""
    assert check_authorization(authorized=True, interactive=False)


def test_check_authorization_not_interactive() -> None:
    """Test non-interactive without authorization."""
    assert not check_authorization(authorized=False, interactive=False)
