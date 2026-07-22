"""Authorization and confirmation logic."""

import os


def request_authorization(target: str) -> bool:
    """Request interactive authorization from user."""
    print("\n⚠️  AUTHORIZATION REQUIRED")
    print(f"   Target: {target}")
    print("\nYou must confirm ownership or explicit authorization to test this target.")
    print("Unauthorized security testing may be illegal.\n")
    response = input(
        "I confirm that I own this target or have explicit permission to test it.\nEnter 'I AM AUTHORIZED' to continue: "
    )
    return response.strip() == "I AM AUTHORIZED"


def get_authorization_from_env() -> bool:
    """Check for authorization via environment variable."""
    return os.environ.get("BARBAROSSA_AUTHORIZED", "").lower() == "true"


def get_authorization(target: str, explicit_auth: bool = False, env_auth: bool = False) -> bool:
    """
    Determine if scan is authorized.

    Args:
        target: Target URL or path
        explicit_auth: Whether --authorized flag was passed
        env_auth: Whether to check environment variable

    Returns:
        True if authorized, False otherwise
    """
    # Explicit flag
    if explicit_auth:
        return True

    # Environment variable (only if env_auth enabled)
    if env_auth and get_authorization_from_env():
        return True

    # Interactive confirmation
    return request_authorization(target)


def check_authorization(
    authorized: bool, target: str | None = None, interactive: bool = True
) -> bool:
    """
    Check and confirm authorization status.

    Returns True if authorized, raises SystemExit if not.
    """
    if authorized:
        return True

    if not interactive:
        return False

    if target:
        return request_authorization(target)

    return False
