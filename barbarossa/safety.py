"""Emergency-stop support shared by static and active scanning."""

import os
from pathlib import Path

DEFAULT_STOP_FILE = "STOP_BARBAROSSA"


class EmergencyStop(RuntimeError):
    """Raised when the operator requests an immediate stop."""


def emergency_stop_path() -> Path:
    """Return the configured emergency-stop file path."""
    return Path(os.environ.get("BARBAROSSA_STOP_FILE", DEFAULT_STOP_FILE))


def is_stop_requested() -> bool:
    """Return whether the emergency-stop file currently exists."""
    return emergency_stop_path().is_file()


def raise_if_stop_requested() -> None:
    """Abort the current operation when the emergency-stop file is present."""
    if is_stop_requested():
        raise EmergencyStop(
            f"Emergency stop requested by {emergency_stop_path()}. "
            "Remove the file before starting another scan."
        )
