import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from barbarossa import __version__
from barbarossa.banner import print_banner
from barbarossa.inspect.scanner import SecurityScanner
from barbarossa.probe.runner import ProbeRunner
from barbarossa.utils.rate_limit import RateLimiter
from barbarossa.authorization import get_authorization
from barbarossa.scope import validate_target_url
from barbarossa.models import ScanResult
from barbarossa.reporting.console import ConsoleReporter
from barbarossa.reporting.json_report import JSONReporter
from barbarossa.reporting.html_report import HTMLReporter
from barbarossa.reporting.sarif_report import SARIFReporter
app = typer.Typer(
    help="BARBAROSSA - Web Application Security Inspection Toolkit",
    add_completion=False,
)
console = Console()
@app.command()
def inspect(
    source: str = typer.Argument(..., help="Source directory to inspect"),
    format: str = typer.Option("console", help="Output format (console, json, html, sarif)"),
    output: str = typer.Option("./reports", help="Output directory"),
    explain: bool = typer.Option(False, help="Add beginner-friendly explanations"),
) -> None:
    """Run static code analysis on a source directory."""
    print_banner()
    source_path = Path(source)
    if not source_path.exists():
        console.print(f"[red]Error: Source directory not found: {source}[/red]")
        sys.exit(1)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    console.print(f"[cyan]📋 Inspecting: {source}[/cyan]")
    scanner = SecurityScanner()
    findings = scanner.scan_directory(str(source_path))
    result = ScanResult(
        start_time=datetime.now(),
        end_time=datetime.now(),
        source_directory=source,
        findings=findings,
    )
    # Report findings
    formats = [f.strip() for f in format.split(",")]
    if "console" in formats:
        console_reporter = ConsoleReporter()
        console_reporter.report(result)
    if "json" in formats:
        JSONReporter().report(result, output_path / "barbarossa-report.json")
    if "html" in formats:
        HTMLReporter().report(result, output_path / "barbarossa-report.html")
    if "sarif" in formats:
        SARIFReporter().report(result, output_path / "barbarossa-report.sarif")
@app.command()
def probe(
    target: str = typer.Argument(..., help="Target URL to probe"),
    authorized: bool = typer.Option(False, help="Confirm authorization for this target"),
    requests_per_second: int = typer.Option(2, help="Rate limit"),
    max_requests: int = typer.Option(150, help="Maximum requests"),
    timeout: float = typer.Option(10.0, help="Request timeout"),
    learning_mode: bool = typer.Option(False, help="Educational mode"),
) -> None:
    """Run active HTTP security checks on a target URL."""
    print_banner()
    # Check authorization
    if not authorized:
        authorized = get_authorization(target, explicit_auth=False, env_auth=True)
        if not authorized:
            console.print("[red]Authorization required. Use --authorized or set BARBAROSSA_AUTHORIZED=true[/red]")
            sys.exit(1)
    console.print(f"[cyan]🔍 Probing: {target}[/cyan]")
    rate_limiter = RateLimiter(
        requests_per_second=requests_per_second,
        max_requests=max_requests,
        timeout_seconds=timeout,
    )
    runner = ProbeRunner(rate_limiter)
    findings = asyncio.run(runner.run_probes(target))
    result = ScanResult(
        start_time=datetime.now(),
        end_time=datetime.now(),
        target_url=target,
        findings=findings,
        authorized=authorized,
        total_requests=rate_limiter.request_count,
    )
    # Report findings
    console_reporter = ConsoleReporter()
    console_reporter.report(result)
@app.command()
def scan(
    source: Optional[str] = typer.Option(None, help="Source directory"),
    target: Optional[str] = typer.Option(None, help="Target URL"),
    config: Optional[str] = typer.Option(None, help="Configuration file"),
    authorized: bool = typer.Option(False, help="Confirm authorization"),
    allowlist: Optional[list[str]] = typer.Option(None, help="Allowlist domain"),
    requests_per_second: int = typer.Option(2, help="Rate limit"),
    max_requests: int = typer.Option(150, help="Maximum requests"),
    timeout: float = typer.Option(10.0, help="Request timeout"),
    format: str = typer.Option("console,json,html", help="Output formats"),
    output: str = typer.Option("./reports", help="Output directory"),
    learning_mode: bool = typer.Option(False, help="Educational mode"),
    explain: bool = typer.Option(False, help="Add explanations"),
    verbose: bool = typer.Option(False, help="Verbose output"),
    dry_run: bool = typer.Option(False, help="Show scope without testing"),
) -> None:
    """Run complete security scan (static + probes)."""
    print_banner()
    # Create output directory
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    start_time = datetime.now()
    all_findings = []
    total_requests = 0
    # Static inspection
    if source:
        source_path = Path(source)
        if source_path.exists():
            console.print(f"[cyan]📋 Inspecting: {source}[/cyan]")
            scanner = SecurityScanner()
            all_findings.extend(scanner.scan_directory(str(source_path)))
            console.print(f"[green]✓ Found {len(scanner.findings)} issues[/green]")
        else:
            console.print(f"[yellow]Source not found: {source}[/yellow]")
    # Active probes
    if target:
        authorized_targets = allowlist or ["localhost", "127.0.0.1"]
        # Validate scope
        is_valid, reason = validate_target_url(target, authorized_targets)
        if not is_valid and not authorized:
            console.print(f"[red]Scope validation failed: {reason}[/red]")
            sys.exit(1)
        # Check authorization
        if not authorized:
            authorized = get_authorization(target, explicit_auth=False, env_auth=True)
            if not authorized:
                console.print("[red]Authorization required[/red]")
                sys.exit(1)
        if not dry_run:
            console.print(f"[cyan]🔍 Probing: {target}[/cyan]")
            rate_limiter = RateLimiter(
                requests_per_second=requests_per_second,
                max_requests=max_requests,
                timeout_seconds=timeout,
            )
            runner = ProbeRunner(rate_limiter)
            probe_findings = asyncio.run(runner.run_probes(target))
            all_findings.extend(probe_findings)
            total_requests = rate_limiter.request_count
            console.print(f"[green]✓ Completed {total_requests} requests[/green]")
        else:
            console.print("[yellow]Dry run mode - no probes will be sent[/yellow]")
    # Create result
    end_time = datetime.now()
    result = ScanResult(
        start_time=start_time,
        end_time=end_time,
        source_directory=source,
        target_url=target,
        findings=all_findings,
        authorized=authorized,
        total_requests=total_requests,
    )
    # Generate reports
    formats = [f.strip() for f in format.split(",")]
    if "console" in formats:
        console_reporter = ConsoleReporter()
        console_reporter.report(result)
    if "json" in formats:
        json_file = output_path / "barbarossa-report.json"
        JSONReporter().report(result, json_file)
        console.print(f"[green]✓ JSON report: {json_file}[/green]")
    if "html" in formats:
        html_file = output_path / "barbarossa-report.html"
        HTMLReporter().report(result, html_file)
        console.print(f"[green]✓ HTML report: {html_file}[/green]")
    if "sarif" in formats:
        sarif_file = output_path / "barbarossa-report.sarif"
        SARIFReporter().report(result, sarif_file)
        console.print(f"[green]✓ SARIF report: {sarif_file}[/green]")
def version_callback(value: bool):
    if value:
        console.print(f"BARBAROSSA {__version__}")
        raise typer.Exit()
@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Show version"
    ),
):
    """BARBAROSSA - Web Application Security Inspection Toolkit."""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())
if __name__ == "__main__":
    app()
