"""JSON reporter for findings."""

import json
from pathlib import Path

from barbarossa.models import ScanResult, Severity
from barbarossa.utils.redaction import redact_evidence
from barbarossa.utils.urls import sanitize_url_for_display


class JSONReporter:
    """Report findings as JSON."""

    def report(self, result: ScanResult, output_path: Path) -> None:
        """Generate JSON report."""
        data = {
            "version": "1.0",
            "tool": "BARBAROSSA",
            "scan_info": {
                "start_time": result.start_time.isoformat(),
                "end_time": result.end_time.isoformat() if result.end_time else None,
                "duration_seconds": result.duration_seconds,
                "authorized": result.authorized,
                "stopped": result.scan_stopped,
            },
            "target": sanitize_url_for_display(result.target_url or "") or None,
            "source": result.source_directory,
            "summary": {
                "total_findings": len(result.findings),
                "critical": len(result.critical_findings),
                "high": len(result.get_findings_by_severity(Severity.HIGH)),
                "medium": len(result.get_findings_by_severity(Severity.MEDIUM)),
                "low": len(result.get_findings_by_severity(Severity.LOW)),
                "info": len(result.get_findings_by_severity(Severity.INFO)),
                "total_requests": result.total_requests,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "description": f.description,
                    "evidence": redact_evidence(f.evidence),
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "endpoint": sanitize_url_for_display(f.endpoint or "") or None,
                    "recommendation": f.recommendation,
                    "references": f.references,
                }
                for f in result.sorted_findings
            ],
        }

        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
