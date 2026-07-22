"""HTML reporter for findings."""

from pathlib import Path

from jinja2 import Environment, select_autoescape

from barbarossa.models import ScanResult, Severity
from barbarossa.utils.redaction import redact_evidence
from barbarossa.utils.urls import sanitize_url_for_display

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BARBAROSSA Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #0f3460;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #d4af37 0%, #c9a961 100%);
            padding: 40px 20px;
            text-align: center;
            color: #1a1a2e;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            letter-spacing: 3px;
        }
        .tagline {
            font-size: 1.1em;
            font-style: italic;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #d4af37;
            margin-bottom: 15px;
            font-size: 1.5em;
            border-bottom: 2px solid #d4af37;
            padding-bottom: 10px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .summary-card {
            background: #16213e;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #d4af37;
        }
        .summary-card h3 {
            color: #d4af37;
            margin-bottom: 10px;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
        }
        .finding {
            background: #16213e;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid;
            padding: 15px;
            overflow: hidden;
        }
        .finding.critical { border-left-color: #ff4444; }
        .finding.high { border-left-color: #ff8844; }
        .finding.medium { border-left-color: #4488ff; }
        .finding.low { border-left-color: #44ff88; }
        .finding.info { border-left-color: #cccccc; }
        .finding-title {
            font-size: 1.1em;
            font-weight: bold;
            color: #e0e0e0;
            margin-bottom: 8px;
        }
        .finding-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-bottom: 10px;
            font-size: 0.9em;
        }
        .meta-item {
            color: #b0b0b0;
        }
        .meta-label {
            color: #d4af37;
            font-weight: bold;
        }
        .finding-description {
            color: #d0d0d0;
            margin-bottom: 10px;
            line-height: 1.5;
        }
        .finding-evidence {
            background: #0f3460;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: #88ff88;
            margin-bottom: 10px;
            word-break: break-all;
        }
        .finding-recommendation {
            background: #1a4d2e;
            padding: 10px;
            border-radius: 4px;
            color: #90ee90;
            margin-bottom: 10px;
            border-left: 3px solid #4caf50;
        }
        .severity-critical { color: #ff4444; }
        .severity-high { color: #ff8844; }
        .severity-medium { color: #4488ff; }
        .severity-low { color: #44ff88; }
        .severity-info { color: #cccccc; }
        .warning {
            background: #4d3319;
            border-left: 4px solid #ff8844;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
            color: #ffcc88;
        }
        .footer {
            background: #0a0a14;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        .stat {
            text-align: center;
            padding: 10px;
            background: #0f3460;
            border-radius: 4px;
        }
        .stat-value {
            font-size: 1.8em;
            font-weight: bold;
            color: #d4af37;
        }
        .stat-label {
            font-size: 0.8em;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BARBAROSSA</h1>
            <p class="tagline">Inspect. Probe. Fortify.</p>
        </div>

        <div class="content">
            <div class="warning">
                <strong>⚠️ Disclaimer:</strong> BARBAROSSA reports security indicators and potential weaknesses.
                A finding does not automatically prove exploitability.
                Manual verification is required.
            </div>

            <div class="section">
                <h2>Scan Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <h3>Total Findings</h3>
                        <div class="value">{{ summary.total }}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Critical</h3>
                        <div class="value" style="color: #ff4444;">{{ summary.critical }}</div>
                    </div>
                    <div class="summary-card">
                        <h3>High</h3>
                        <div class="value" style="color: #ff8844;">{{ summary.high }}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Medium</h3>
                        <div class="value" style="color: #4488ff;">{{ summary.medium }}</div>
                    </div>
                </div>

                <div class="stats">
                    <div class="stat">
                        <div class="stat-value">{{ duration }}</div>
                        <div class="stat-label">Duration (s)</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{{ total_requests }}</div>
                        <div class="stat-label">Requests</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{{ scan_date }}</div>
                        <div class="stat-label">Date</div>
                    </div>
                </div>
            </div>

            {% if target %}
            <div class="section">
                <h2>Target Information</h2>
                <p><strong>URL:</strong> {{ target }}</p>
                <p><strong>Authorized:</strong> {{ 'Yes' if authorized else 'No' }}</p>
            </div>
            {% endif %}

            {% if source %}
            <div class="section">
                <h2>Source Directory</h2>
                <p>{{ source }}</p>
            </div>
            {% endif %}

            <div class="section">
                <h2>Findings</h2>
                {% if findings %}
                    {% for finding in findings %}
                    <div class="finding {{ finding.severity|lower }}">
                        <div class="finding-title">{{ finding.title }}</div>
                        <div class="finding-meta">
                            <div class="meta-item">
                                <span class="meta-label">ID:</span> {{ finding.id }}
                            </div>
                            <div class="meta-item">
                                <span class="meta-label">Severity:</span>
                                <span class="severity-{{ finding.severity|lower }}">{{ finding.severity }}</span>
                            </div>
                            <div class="meta-item">
                                <span class="meta-label">Confidence:</span> {{ finding.confidence }}
                            </div>
                            <div class="meta-item">
                                <span class="meta-label">Category:</span> {{ finding.category }}
                            </div>
                        </div>
                        {% if finding.file_path %}
                        <div class="meta-item">
                            <span class="meta-label">Location:</span> {{ finding.file_path }}:{{ finding.line_number }}
                        </div>
                        {% endif %}
                        {% if finding.endpoint %}
                        <div class="meta-item">
                            <span class="meta-label">Endpoint:</span> {{ finding.endpoint }}
                        </div>
                        {% endif %}
                        <div class="finding-description">{{ finding.description }}</div>
                        <div class="finding-evidence"><strong>Evidence:</strong> {{ finding.evidence }}</div>
                        <div class="finding-recommendation"><strong>Recommendation:</strong> {{ finding.recommendation }}</div>
                    </div>
                    {% endfor %}
                {% else %}
                <p><strong style="color: #44ff88;">✓ No findings!</strong></p>
                {% endif %}
            </div>
        </div>

        <div class="footer">
            <p>BARBAROSSA v0.1.0 | Deterministic Web Application Security Testing</p>
            <p>Generated on {{ scan_date }} | Duration: {{ duration }}s</p>
        </div>
    </div>
</body>
</html>
"""


class HTMLReporter:
    """Report findings as HTML."""

    def report(self, result: ScanResult, output_path: Path) -> None:
        """Generate HTML report."""
        environment = Environment(
            autoescape=select_autoescape(
                enabled_extensions=("html", "xml"),
                default_for_string=True,
                default=True,
            )
        )
        template = environment.from_string(HTML_TEMPLATE)

        findings_data = []
        for finding in result.sorted_findings:
            findings_data.append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "description": finding.description,
                    "evidence": redact_evidence(finding.evidence),
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "endpoint": sanitize_url_for_display(finding.endpoint or "") or None,
                    "recommendation": finding.recommendation,
                }
            )

        context = {
            "summary": {
                "total": len(result.findings),
                "critical": len(result.critical_findings),
                "high": len(result.get_findings_by_severity(Severity.HIGH)),
                "medium": len(result.get_findings_by_severity(Severity.MEDIUM)),
                "low": len(result.get_findings_by_severity(Severity.LOW)),
                "info": len(result.get_findings_by_severity(Severity.INFO)),
            },
            "findings": findings_data,
            "target": sanitize_url_for_display(result.target_url or "") or None,
            "source": result.source_directory,
            "authorized": result.authorized,
            "scan_date": result.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": round(result.duration_seconds, 1),
            "total_requests": result.total_requests,
        }

        html_content = template.render(**context)
        output_path.write_text(html_content, encoding="utf-8")
