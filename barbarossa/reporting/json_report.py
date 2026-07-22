"""JSON reporter for findings."""

import json
from datetime import datetime
from pathlib import Path
from barbarossa.models import ScanResult


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
            "target": result.target_url,
            "source": result.source_directory,
            "summary": {
                "total_findings": len(result.findings),
                "critical": len(result.critical_findings),
                "high": len(result.get_findings_by_severity("HIGH")),
                "medium": len(result.get_findings_by_severity("MEDIUM")),
                "low": len(result.get_findings_by_severity("LOW")),
                "info": len(result.get_findings_by_severity("INFO")),
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
                    "evidence": f.evidence,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "endpoint": f.endpoint,
                    "recommendation": f.recommendation,
                    "references": f.references,
                }
                for f in result.sorted_findings
            ],
        }
        
        output_path.write_text(json.dumps(data, indent=2))
