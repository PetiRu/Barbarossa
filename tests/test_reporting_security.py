"""Security tests for generated reports."""

import json
from datetime import datetime
from pathlib import Path

from barbarossa.models import Category, Confidence, Finding, ScanResult, Severity
from barbarossa.reporting.html_report import HTMLReporter
from barbarossa.reporting.json_report import JSONReporter


def _result() -> ScanResult:
    return ScanResult(
        start_time=datetime.now(),
        end_time=datetime.now(),
        target_url="https://user:pass@example.com/?token=secret-token",
        findings=[
            Finding(
                id="TEST",
                title="<script>alert(1)</script>",
                category=Category.SECRETS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="Untrusted content",
                evidence="<script>alert(2)</script> API_KEY=super-secret-value",
                endpoint="https://example.com/path?password=hunter2",
                recommendation="Remove it",
            )
        ],
    )


def test_html_report_escapes_and_redacts(tmp_path: Path) -> None:
    """Finding data cannot inject markup or expose assignment-style secrets."""
    output = tmp_path / "report.html"
    HTMLReporter().report(_result(), output)
    html = output.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "super-secret-value" not in html
    assert "pass@example.com" not in html


def test_json_report_redacts_urls_and_evidence(tmp_path: Path) -> None:
    """Machine-readable reports apply the same disclosure controls."""
    output = tmp_path / "report.json"
    JSONReporter().report(_result(), output)
    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["target"] == "https://example.com/?token=%5BREDACTED%5D"
    assert "super-secret-value" not in data["findings"][0]["evidence"]
    assert "hunter2" not in data["findings"][0]["endpoint"]
