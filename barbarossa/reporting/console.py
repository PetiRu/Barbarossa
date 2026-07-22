"""Console reporter for findings."""

from rich.console import Console
from rich.panel import Panel

from barbarossa.models import ScanResult, Severity


class ConsoleReporter:
    """Report findings to console with colors."""

    def __init__(self) -> None:
        """Initialize console reporter."""
        self.console = Console()

    def report(self, result: ScanResult) -> None:
        """Print scan results to console."""
        self.console.print(Panel.fit("[bold cyan]BARBAROSSA SCAN RESULTS[/bold cyan]"))

        # Summary
        self._print_summary(result)

        # Findings by severity
        self._print_findings(result)

    def _print_summary(self, result: ScanResult) -> None:
        """Print scan summary."""
        self.console.print("\n[bold]Scan Summary[/bold]")
        self.console.print(f"  Duration: {result.duration_seconds:.1f}s")
        self.console.print(f"  Total Requests: {result.total_requests}")
        self.console.print(f"  Total Findings: {len(result.findings)}")
        self.console.print(f"  Authorized: {'Yes' if result.authorized else 'No'}")
        self.console.print(f"  Stopped: {'Yes' if result.scan_stopped else 'No'}")

        # Severity breakdown
        critical = len(result.critical_findings)
        high = len(result.get_findings_by_severity(Severity.HIGH))
        medium = len(result.get_findings_by_severity(Severity.MEDIUM))
        low = len(result.get_findings_by_severity(Severity.LOW))
        info = len(result.get_findings_by_severity(Severity.INFO))

        if critical > 0:
            self.console.print(f"  [red]● Critical: {critical}[/red]")
        if high > 0:
            self.console.print(f"  [yellow]● High: {high}[/yellow]")
        if medium > 0:
            self.console.print(f"  [blue]● Medium: {medium}[/blue]")
        if low > 0:
            self.console.print(f"  ● Low: {low}")
        if info > 0:
            self.console.print(f"  ● Info: {info}")

    def _print_findings(self, result: ScanResult) -> None:
        """Print findings by severity."""
        if not result.findings:
            self.console.print("\n[green]✓ No findings![/green]")
            return

        self.console.print("\n[bold]Findings[/bold]")

        for finding in result.sorted_findings:
            self._print_finding(finding)

    def _print_finding(self, finding) -> None:  # type: ignore
        """Print individual finding."""
        # Severity color
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "blue",
            "LOW": "cyan",
            "INFO": "white",
        }.get(finding.severity.value, "white")

        severity_symbol = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🔵",
            "LOW": "🟢",
            "INFO": "⚪",
        }.get(finding.severity.value, "")

        self.console.print(f"\n{severity_symbol} [{severity_color}]{finding.title}[/{severity_color}]")
        self.console.print(f"   Rule ID: {finding.id}")
        self.console.print(f"   Category: {finding.category.value}")
        self.console.print(f"   Severity: {finding.severity.value} | Confidence: {finding.confidence.value}")

        if finding.file_path:
            self.console.print(f"   File: {finding.file_path}:{finding.line_number}")
        if finding.endpoint:
            self.console.print(f"   Endpoint: {finding.endpoint}")

        self.console.print(f"   Description: {finding.description}")
        self.console.print(f"   Evidence: {finding.evidence}")
        self.console.print(f"   Recommendation: {finding.recommendation}")
