"""Command-line interface for BARBAROSSA."""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console
from rich.markup import escape

from barbarossa import __version__
from barbarossa.authorization import get_authorization
from barbarossa.banner import print_banner
from barbarossa.config import ConfigError, ScanConfig, load_scan_config
from barbarossa.inspect.scanner import SecurityScanner
from barbarossa.models import Finding, ScanResult
from barbarossa.probe.runner import ProbeRunner
from barbarossa.reporting.console import ConsoleReporter
from barbarossa.reporting.html_report import HTMLReporter
from barbarossa.reporting.json_report import JSONReporter
from barbarossa.reporting.sarif_report import SARIFReporter
from barbarossa.safety import EmergencyStop, is_stop_requested, raise_if_stop_requested
from barbarossa.scope import validate_target_url
from barbarossa.utils.rate_limit import RateLimiter

app = typer.Typer(
    help="BARBAROSSA - Web Application Security Inspection Toolkit",
    add_completion=False,
)
console = Console()
SUPPORTED_FORMATS = {"console", "json", "html", "sarif"}


def _abort(message: str, exit_code: int = 1) -> NoReturn:
    console.print(f"[red]Error: {message}[/red]")
    raise typer.Exit(exit_code)


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)


def _formats(value: str) -> list[str]:
    formats = [item.strip().lower() for item in value.split(",") if item.strip()]
    unsupported = sorted(set(formats) - SUPPORTED_FORMATS)
    if not formats or unsupported:
        _abort(
            "Output formats must be one or more of console, json, html, sarif"
            + (f"; unsupported: {', '.join(unsupported)}" if unsupported else "")
        )
    return formats


def _authorization(target: str, explicit: bool) -> bool:
    if explicit:
        return True
    if get_authorization(target, explicit_auth=False, env_auth=True):
        return True
    _abort(
        "Authorization required. Use --authorized, set BARBAROSSA_AUTHORIZED=true, "
        "or confirm interactively."
    )


def _validate_scope(target: str, authorized_targets: list[str]) -> None:
    valid, reason = validate_target_url(target, authorized_targets)
    if not valid:
        _abort(f"Scope validation failed: {reason}")


def _make_rate_limiter(
    requests_per_second: float,
    max_requests: int,
    timeout: float,
    max_redirects: int,
    max_consecutive_errors: int,
) -> RateLimiter:
    return RateLimiter(
        requests_per_second=requests_per_second,
        max_requests=max_requests,
        request_timeout_seconds=timeout,
        max_redirects=max_redirects,
        max_consecutive_errors=max_consecutive_errors,
    )


def _render_reports(result: ScanResult, formats: list[str], output_path: Path) -> None:
    if "console" in formats:
        ConsoleReporter().report(result)
    if "json" in formats:
        json_file = output_path / "barbarossa-report.json"
        JSONReporter().report(result, json_file)
        console.print(f"[green]JSON report: {json_file}[/green]")
    if "html" in formats:
        html_file = output_path / "barbarossa-report.html"
        HTMLReporter().report(result, html_file)
        console.print(f"[green]HTML report: {html_file}[/green]")
    if "sarif" in formats:
        sarif_file = output_path / "barbarossa-report.sarif"
        SARIFReporter().report(result, sarif_file)
        console.print(f"[green]SARIF report: {sarif_file}[/green]")


def _learning_summary(findings: list[Finding]) -> None:
    console.print("\n[bold cyan]Learning mode[/bold cyan]")
    if not findings:
        console.print("No indicators were found. This is not proof that the application is secure.")
        return
    for finding in sorted(findings):
        console.print(f"[bold]{escape(finding.id)}[/bold]: {escape(finding.description)}")
        console.print(f"  Fix: {escape(finding.recommendation)}")


@app.command()
def inspect(
    source: str = typer.Argument(..., help="Source directory to inspect"),
    format: str = typer.Option("console", help="Output format (console, json, html, sarif)"),
    output: str = typer.Option("./reports", help="Output directory"),
    explain: bool = typer.Option(False, help="Add beginner-friendly explanations"),
    verbose: bool = typer.Option(False, help="Enable diagnostic logging"),
) -> None:
    """Run static code analysis on a source directory."""
    print_banner()
    _configure_logging(verbose)
    try:
        raise_if_stop_requested()
        source_path = Path(source)
        if not source_path.is_dir():
            _abort(f"Source directory not found: {source}")

        output_path = Path(output)
        output_path.mkdir(parents=True, exist_ok=True)
        start_time = datetime.now()
        console.print(f"[cyan]Inspecting: {source}[/cyan]")
        scanner = SecurityScanner()
        findings = scanner.scan_directory(str(source_path))
        result = ScanResult(
            start_time=start_time,
            end_time=datetime.now(),
            source_directory=source,
            findings=findings,
            scan_stopped=scanner.stopped,
        )
        _render_reports(result, _formats(format), output_path)
        if explain:
            _learning_summary(findings)
    except EmergencyStop as exc:
        _abort(str(exc), exit_code=2)


@app.command()
def probe(
    target: str = typer.Argument(..., help="Target URL to probe"),
    authorized: bool = typer.Option(False, help="Confirm authorization for this target"),
    allowlist: list[str] | None = typer.Option(None, help="Explicitly allowed host or host:port"),
    requests_per_second: float = typer.Option(2.0, min=0.01, help="Rate limit"),
    max_requests: int = typer.Option(150, min=1, help="Maximum requests"),
    timeout: float = typer.Option(10.0, min=0.01, help="Request timeout"),
    max_redirects: int = typer.Option(3, min=1, help="Maximum validated redirects"),
    learning_mode: bool = typer.Option(False, help="Educational mode"),
    verbose: bool = typer.Option(False, help="Enable diagnostic logging"),
) -> None:
    """Run active HTTP security checks on an authorized target."""
    print_banner()
    _configure_logging(verbose)
    try:
        raise_if_stop_requested()
        authorized_targets = allowlist or ["localhost", "127.0.0.1", "::1"]
        _validate_scope(target, authorized_targets)
        confirmed = _authorization(target, authorized)

        limiter = _make_rate_limiter(requests_per_second, max_requests, timeout, max_redirects, 3)
        console.print(f"[cyan]Probing: {target}[/cyan]")
        runner = ProbeRunner(limiter, authorized_targets)
        start_time = datetime.now()
        findings = asyncio.run(runner.run_probes(target))
        result = ScanResult(
            start_time=start_time,
            end_time=datetime.now(),
            target_url=target,
            findings=findings,
            authorized=confirmed,
            total_requests=limiter.request_count,
            scan_stopped=is_stop_requested(),
        )
        ConsoleReporter().report(result)
        if learning_mode:
            _learning_summary(findings)
    except EmergencyStop as exc:
        _abort(str(exc), exit_code=2)


def _resolve_scan_settings(
    config: str | None,
    source: str | None,
    target: str | None,
    allowlist: list[str] | None,
    requests_per_second: float | None,
    max_requests: int | None,
    timeout: float | None,
    max_redirects: int | None,
    format: str | None,
    output: str | None,
) -> tuple[
    ScanConfig,
    str | None,
    str | None,
    list[str],
    float,
    int,
    float,
    int,
    str,
    str,
]:
    try:
        settings = load_scan_config(config)
    except ConfigError as exc:
        _abort(str(exc))

    resolved_source = source if source is not None else settings.source_directory
    resolved_target = target if target is not None else settings.target_url
    targets = list(dict.fromkeys([*settings.authorized_targets, *(allowlist or [])]))
    rps = requests_per_second if requests_per_second is not None else settings.requests_per_second
    request_limit = max_requests if max_requests is not None else settings.max_requests
    request_timeout = timeout if timeout is not None else settings.request_timeout
    redirect_limit = max_redirects if max_redirects is not None else settings.max_redirects
    formats = format or ",".join(settings.formats)
    output_directory = output or settings.output_directory
    return (
        settings,
        resolved_source,
        resolved_target,
        targets,
        rps,
        request_limit,
        request_timeout,
        redirect_limit,
        formats,
        output_directory,
    )


@app.command()
def scan(
    source: str | None = typer.Option(None, help="Source directory"),
    target: str | None = typer.Option(None, help="Target URL"),
    config: str | None = typer.Option(None, help="TOML configuration file"),
    authorized: bool = typer.Option(False, help="Confirm authorization"),
    allowlist: list[str] | None = typer.Option(None, help="Explicitly allowed host or host:port"),
    requests_per_second: float | None = typer.Option(None, min=0.01, help="Override rate limit"),
    max_requests: int | None = typer.Option(None, min=1, help="Override maximum requests"),
    timeout: float | None = typer.Option(None, min=0.01, help="Override request timeout"),
    max_redirects: int | None = typer.Option(
        None, min=1, help="Override maximum validated redirects"
    ),
    format: str | None = typer.Option(None, help="Output formats"),
    output: str | None = typer.Option(None, help="Output directory"),
    learning_mode: bool = typer.Option(False, help="Educational mode"),
    explain: bool = typer.Option(False, help="Add explanations"),
    verbose: bool = typer.Option(False, help="Verbose output"),
    dry_run: bool = typer.Option(False, help="Show scope without active requests"),
) -> None:
    """Run a complete static and authorized active security scan."""
    print_banner()
    (
        settings,
        source,
        target,
        authorized_targets,
        requests_per_second,
        max_requests,
        timeout,
        max_redirects,
        format,
        output,
    ) = _resolve_scan_settings(
        config,
        source,
        target,
        allowlist,
        requests_per_second,
        max_requests,
        timeout,
        max_redirects,
        format,
        output,
    )
    learning_mode = learning_mode or explain or settings.learning_mode
    verbose = verbose or settings.verbose
    dry_run = dry_run or settings.dry_run
    _configure_logging(verbose)

    if not source and not target:
        _abort("Provide --source, --target, or a configuration containing one of them")

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    start_time = datetime.now()
    findings: list[Finding] = []
    total_requests = 0
    confirmed = False
    stopped = False

    try:
        raise_if_stop_requested()
        if source and settings.static_inspection:
            source_path = Path(source)
            if not source_path.is_dir():
                _abort(f"Source directory not found: {source}")
            console.print(f"[cyan]Inspecting: {source}[/cyan]")
            scanner = SecurityScanner()
            findings.extend(scanner.scan_directory(str(source_path)))
            stopped = scanner.stopped
            console.print(f"[green]Found {len(scanner.findings)} static indicators[/green]")

        if target and settings.active_probes:
            _validate_scope(target, authorized_targets)
            if dry_run:
                console.print(f"[yellow]Dry run: target in scope: {target}[/yellow]")
                console.print(
                    "[yellow]Planned probes: HTTPS, headers, exposed files, directory listing[/yellow]"
                )
            else:
                raise_if_stop_requested()
                confirmed = _authorization(target, authorized)
                limiter = _make_rate_limiter(
                    requests_per_second,
                    max_requests,
                    timeout,
                    max_redirects,
                    settings.max_consecutive_errors,
                )
                console.print(f"[cyan]Probing: {target}[/cyan]")
                runner = ProbeRunner(limiter, authorized_targets)
                findings.extend(asyncio.run(runner.run_probes(target)))
                total_requests = limiter.request_count
                stopped = stopped or is_stop_requested()
                console.print(f"[green]Completed {total_requests} requests[/green]")
    except EmergencyStop as exc:
        stopped = True
        console.print(f"[yellow]{exc}[/yellow]")

    result = ScanResult(
        start_time=start_time,
        end_time=datetime.now(),
        source_directory=source if settings.static_inspection else None,
        target_url=target if settings.active_probes else None,
        findings=findings,
        authorized=confirmed,
        total_requests=total_requests,
        scan_stopped=stopped,
    )
    _render_reports(result, _formats(format), output_path)
    if learning_mode:
        _learning_summary(findings)


@app.command()
def report(
    file: str | None = typer.Option(None, help="JSON report file to view"),
    directory: str = typer.Option("./reports", "--dir", help="Directory containing reports"),
) -> None:
    """View the latest or a specific JSON scan report in the terminal."""
    print_banner()
    report_file = Path(file) if file else Path(directory) / "barbarossa-report.json"
    if not report_file.is_file():
        _abort(f"Report file not found: {report_file}")
    try:
        result = ScanResult.from_json(report_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError) as exc:
        _abort(f"Could not load report: {exc}")
    ConsoleReporter().report(result)


def version_callback(value: bool) -> None:
    """Print the package version for the eager --version option."""
    if value:
        console.print(f"BARBAROSSA {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool | None = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Show version"
    ),
) -> None:
    """BARBAROSSA - Web Application Security Inspection Toolkit."""
    del version
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())


if __name__ == "__main__":
    app()
