# Reports

BARBAROSSA generates reports in multiple formats for different use cases.

## Console Report

Real-time output to terminal:

```bash
barbarossa scan --source . --target http://localhost:8000 --format console
```

Shows:
- Colored severity indicators
- Summary statistics
- Detailed findings
- Progress updates

## JSON Report

Structured data for integration:

```bash
barbarossa scan --format json
```

Output: `barbarossa-report.json`

Use cases:
- CI/CD integration
- Automated processing
- Integration with SIEM
- Custom reporting

Example structure:

```json
{
  "version": "1.0",
  "tool": "BARBAROSSA",
  "scan_info": {...},
  "summary": {...},
  "findings": [...]
}
```

## HTML Report

Beautiful, shareable report:

```bash
barbarossa scan --format html
```

Output: `barbarossa-report.html`

Features:
- BARBAROSSA branding
- Severity charts
- Searchable findings
- Print-friendly
- Dark theme

## SARIF Report

GitHub-compatible format:

```bash
barbarossa scan --format sarif
```

Output: `barbarossa-report.sarif`

Integrates with GitHub Security tab:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: barbarossa-report.sarif
```

## Multiple Formats

Generate all at once:

```bash
barbarossa scan \
  --format console,json,html,sarif \
  --output ./reports
```

Output:
- `barbarossa-report.json`
- `barbarossa-report.html`
- `barbarossa-report.sarif`

## Report Contents

All reports include:

- Scan duration and timestamp
- Target URL and source directory
- Authorization status
- Total requests made
- Summary by severity
- Detailed findings
- Recommendations

Each finding shows:

- Rule ID and title
- Category and severity
- Confidence level
- File/endpoint location
- Description and evidence
- Remediation recommendation
- References for more information
