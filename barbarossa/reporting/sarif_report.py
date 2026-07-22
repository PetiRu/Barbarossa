"""SARIF reporter for findings."""

import json
from pathlib import Path
from barbarossa.models import ScanResult


class SARIFReporter:
    """Report findings in SARIF format for GitHub integration."""
    
    def report(self, result: ScanResult, output_path: Path) -> None:
        """Generate SARIF report."""
        # Map BARBAROSSA severity to SARIF level
        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        
        rules = {}
        results = []
        
        for finding in result.sorted_findings:
            # Create rule
            if finding.id not in rules:
                rules[finding.id] = {
                    "id": finding.id,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": finding.recommendation},
                    "defaultConfiguration": {
                        "level": severity_map.get(finding.severity.value, "warning"),
                    },
                }
            
            # Create result
            result_entry: dict = {
                "ruleId": finding.id,
                "level": severity_map.get(finding.severity.value, "warning"),
                "message": {"text": finding.description},
                "locations": [],
            }
            
            # Add location if available
            if finding.file_path:
                result_entry["locations"].append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {
                            "startLine": finding.line_number or 1,
                        }
                    }
                })
            elif finding.endpoint:
                result_entry["locations"].append({
                    "logicalLocations": [{
                        "name": finding.endpoint,
                    }]
                })
            
            results.append(result_entry)
        
        # Build SARIF document
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BARBAROSSA",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/PetiRu/Barbarossa",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "scanTarget": result.target_url or result.source_directory,
                        "scanDuration": result.duration_seconds,
                        "requestsCount": result.total_requests,
                    }
                }
            ]
        }
        
        output_path.write_text(json.dumps(sarif, indent=2))
