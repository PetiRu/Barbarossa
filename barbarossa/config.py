"""Typed TOML configuration loading for BARBAROSSA scans."""

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when a configuration file cannot be loaded safely."""


@dataclass(frozen=True)
class ScanConfig:
    """Resolved scan configuration with conservative defaults."""

    target_url: str | None = None
    source_directory: str | None = None
    authorized_targets: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
    requests_per_second: float = 2.0
    max_requests: int = 150
    request_timeout: float = 10.0
    max_redirects: int = 3
    max_consecutive_errors: int = 3
    formats: tuple[str, ...] = ("console", "json", "html")
    output_directory: str = "./reports"
    static_inspection: bool = True
    active_probes: bool = True
    learning_mode: bool = False
    verbose: bool = False
    dry_run: bool = False


def _table(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a TOML table")
    return value


def _optional_string(table: dict[str, Any], key: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} must be a non-empty string")
    return value


def _string(table: dict[str, Any], key: str, default: str) -> str:
    value = table.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{key} must be a non-empty string")
    return value


def _positive_float(table: dict[str, Any], key: str, default: float) -> float:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        raise ConfigError(f"{key} must be greater than zero")
    return float(value)


def _positive_int(table: dict[str, Any], key: str, default: int) -> int:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{key} must be a positive integer")
    return value


def _boolean(table: dict[str, Any], key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def _string_tuple(table: dict[str, Any], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = table.get(key, list(default))
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ConfigError(f"{key} must be an array of non-empty strings")
    return tuple(value)


def load_scan_config(path: str | Path | None) -> ScanConfig:
    """Load a scan configuration, or return defaults when no path is supplied."""
    if path is None:
        return ScanConfig()

    config_path = Path(path)
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Could not read configuration: {config_path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {config_path}: {exc}") from exc

    scan = _table(raw, "scan")
    security = _table(raw, "security")
    output = _table(raw, "output")
    features = _table(raw, "features")

    defaults = ScanConfig()
    return ScanConfig(
        target_url=_optional_string(scan, "target_url"),
        source_directory=_optional_string(scan, "source_directory"),
        authorized_targets=_string_tuple(scan, "authorized_targets", defaults.authorized_targets),
        requests_per_second=_positive_float(
            security, "requests_per_second", defaults.requests_per_second
        ),
        max_requests=_positive_int(security, "max_requests", defaults.max_requests),
        request_timeout=_positive_float(security, "request_timeout", defaults.request_timeout),
        max_redirects=_positive_int(security, "max_redirects", defaults.max_redirects),
        max_consecutive_errors=_positive_int(
            security, "max_consecutive_errors", defaults.max_consecutive_errors
        ),
        formats=_string_tuple(output, "formats", defaults.formats),
        output_directory=_string(output, "output_directory", defaults.output_directory),
        static_inspection=_boolean(features, "static_inspection", defaults.static_inspection),
        active_probes=_boolean(features, "active_probes", defaults.active_probes),
        learning_mode=_boolean(features, "learning_mode", defaults.learning_mode),
        verbose=_boolean(features, "verbose", defaults.verbose),
        dry_run=_boolean(features, "dry_run", defaults.dry_run),
    )
