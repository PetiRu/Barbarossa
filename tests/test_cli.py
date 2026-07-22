"""End-to-end CLI safety tests."""

from pathlib import Path

from typer.testing import CliRunner

from barbarossa.cli import app

runner = CliRunner()


def test_authorized_flag_does_not_bypass_scope() -> None:
    """Authorization confirmation is never a scope override."""
    result = runner.invoke(app, ["probe", "http://example.com", "--authorized"])
    assert result.exit_code == 1
    assert "Scope validation failed" in result.output


def test_scan_loads_config_and_performs_dry_run(tmp_path: Path) -> None:
    """The scan command uses TOML target, scope, and feature settings."""
    config = tmp_path / "scan.toml"
    config.write_text(
        f"""
[scan]
target_url = "https://example.com"
authorized_targets = ["example.com"]

[output]
formats = ["json"]
output_directory = "{tmp_path.as_posix()}"

[features]
dry_run = true
""",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", "--config", str(config)])

    assert result.exit_code == 0
    assert "Dry run: target in scope" in result.output
    assert (tmp_path / "barbarossa-report.json").is_file()


def test_emergency_stop_blocks_new_scan(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The emergency-stop file prevents any scan stage from starting."""
    stop_file = tmp_path / "STOP"
    stop_file.write_text("stop", encoding="utf-8")
    monkeypatch.setenv("BARBAROSSA_STOP_FILE", str(stop_file))

    result = runner.invoke(app, ["inspect", str(tmp_path)])
    assert result.exit_code == 2
    assert "Emergency stop requested" in result.output
