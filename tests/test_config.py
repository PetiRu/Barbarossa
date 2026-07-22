"""Tests for TOML configuration loading."""

from pathlib import Path

import pytest

from barbarossa.config import ConfigError, load_scan_config


def test_load_scan_config(tmp_path: Path) -> None:
    """All supported configuration tables are applied."""
    config_file = tmp_path / "scan.toml"
    config_file.write_text(
        """
[scan]
target_url = "https://example.com"
source_directory = "./src"
authorized_targets = ["example.com"]

[security]
requests_per_second = 4
max_requests = 20
request_timeout = 5
max_redirects = 2
max_consecutive_errors = 2

[output]
formats = ["json"]
output_directory = "./out"

[features]
static_inspection = false
active_probes = true
learning_mode = true
verbose = true
dry_run = true
""",
        encoding="utf-8",
    )

    config = load_scan_config(config_file)
    assert config.target_url == "https://example.com"
    assert config.authorized_targets == ("example.com",)
    assert config.requests_per_second == 4
    assert config.max_redirects == 2
    assert config.formats == ("json",)
    assert config.learning_mode
    assert config.dry_run


def test_invalid_config_type_is_rejected(tmp_path: Path) -> None:
    """Invalid safety values fail closed."""
    config_file = tmp_path / "bad.toml"
    config_file.write_text("[security]\nmax_requests = 0\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="max_requests"):
        load_scan_config(config_file)
