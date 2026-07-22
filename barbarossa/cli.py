"""Command-line interface for BARBAROSSA."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console

from barbarossa import print_banner, __version__
from barbarossa.banner import print_banner as show_banner
from barbarossa.models import ScanResult
from barbarossa.scope import validate_target_url
from barbarossa.authorization import get_authorization
from barbarossa.inspect.scanner import SecurityScanner
from barbarossa.probe.runner import ProbeRunner
from barbarossa.reporting.console import ConsoleReporter
from barbarossa.reporting.json_report import JSONReporter
from barbarossa.reporting.html_report import HTMLReporter
from barbarossa.reporting.sarif_report import SARIFReporter
from barbarossa.utils.rate_limit import RateLimiter


app = typer.Typer(help="BARBAROSSA - Web Application Security Inspection Toolkit")
console = Console()


@app.command()
def inspect(
    source: str = typer.Argument(..., help="Source directory to scan"),
    explain: bool = typer.Option(False, help="Add beginner-friendly explanations"),
    verbose: bool = typer.Option(False, help="Verbose output"),
    output: str = typer.Option("./reports", help="Output directory"),
) -> None:
    """Perform static code inspection."""
    show_banner()
    
    source_path = Path(source)
    if not source_path.exists():
        console.print(f"[red]Error: Source directory not found: {source}[/red]")
        sys.exit(1)
    
    console.print(f"[cyan]Scanning: {source_path.resolve()}[/cyan]")
    
    scanner = SecurityScanner()
    findings = scanner.scan_directory(str(source_path))
    
    result = ScanResult(
        start_time=datetime.now(),
        end_time=datetime.now(),
        source_directory=source,
        findings=findings,
        authorized=True,
    )
    
    # Report findings
    console_reporter = ConsoleReporter()
    console_reporter.report(result)


@app.command()
def probe(
    target: str = typer.Argument(..., help="Target URL to probe"),
    authorized: bool = typer.Option(False, help="Confirm authorization"),
    allowlist: Optional[list[str]] = typer.Option(None, help="Allowlist domain"),
    requests_per_second: int = typer.Option(2, help="Rate limit"),
    max_requests: int = typer.Option(150, help="Maximum requests"),
    timeout: float = typer.Option(10.0, help="Request timeout"),
    format: str = typer.Option("console", help="Output format"),
    output: str = typer.Option("./reports", help="Output directory"),
    dry_run: bool = typer.Option(False, help="Show scope without testing"),
    verbose: bool = typer.Option(False, help="Verbose output"),
) -> None:
    """Run active HTTP security probes."""
    show_banner()
    
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
    
    console.print(f"[cyan]Probing: {target}[/cyan]")
    console.print(f"[dim]Rate limit: {requests_per_second} req/s[/dim]")
    
    if dry_run:
        console.print("[yellow]Dry run mode - no requests will be sent[/yellow]")
        return
    
    # Run probes
    rate_limiter = RateLimiter(
        requests_per_second=requests_per_second,
        max_requests=max_requests,
        request_timeout_seconds=timeout,
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
    show_banner()
    
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
                request_timeout_seconds=timeout,
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


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version"),
) -> None:
    """BARBAROSSA - Web Application Security Inspection Toolkit."""
    if version:
        console.print(f"BARBAROSSA {__version__}")
        sys.exit(0)
    
    if ctx.invoked_subcommand is None:
        show_banner()
        console.print(typer.get_app_dir("barbarossa"))


if __name__ == "__main__":
    app()
