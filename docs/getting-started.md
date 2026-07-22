# Getting Started with BARBAROSSA

## Installation

### From Source

```bash
git clone https://github.com/PetiRu/Barbarossa.git
cd Barbarossa

# Create virtual environment
python3.12 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install
pip install -e .
```

### Quick Test

```bash
# Static inspection
barbarossa inspect .

# Or use the CLI
python main.py
```

## Your First Scan

### 1. Start the Vulnerable Demo

The repository includes a vulnerable demo app for learning:

```bash
cd examples/vulnerable_demo_app
pip install -r requirements.txt
python app.py
```

The app runs on `http://127.0.0.1:8000`

### 2. Run a Static Inspection

```bash
barbarossa inspect examples/vulnerable_demo_app
```

You should see findings like:
- Hardcoded secrets
- Debug mode enabled
- Exposed configuration endpoints

### 3. Run Active Probes

In another terminal:

```bash
barbarossa probe http://127.0.0.1:8000 --authorized
```

You should see findings like:
- Missing security headers
- Exposed endpoints

### 4. Generate Reports

```bash
barbarossa scan \
  --source examples/vulnerable_demo_app \
  --target http://127.0.0.1:8000 \
  --authorized \
  --format console,json,html
```

Reports appear in `./reports/`:
- `barbarossa-report.json` - Structured data
- `barbarossa-report.html` - Beautiful report
- `barbarossa-report.sarif` - GitHub integration

## Testing Your Own Code

### Inspect Your Source

```bash
barbarossa inspect ./my-website
```

BARBAROSSA will scan for:
- Hardcoded credentials
- Dangerous code patterns
- Weak cryptography
- SQL injection indicators
- XSS vulnerabilities
- And more...

### Probe Your Local Server

```bash
# Start your server
python -m http.server 8000 &

# In another terminal
barbarossa probe http://localhost:8000 --authorized
```

## Configuration File

Create `config.toml`:

```toml
[scan]
target_url = "http://localhost:8000"
source_directory = "./src"

[security]
requests_per_second = 2
max_requests = 150
```

Run with config:

```bash
barbarossa scan --config config.toml --authorized
```

## Command Reference

### Inspect Only

```bash
barbarossa inspect ./my-website [options]
```

### Probe Only

```bash
barbarossa probe http://localhost:8000 [options]
```

### Full Scan

```bash
barbarossa scan [options]
```

### Common Options

```
--authorized              Confirm authorization
--format console,json,html Output formats
--output ./reports        Report directory
--verbose                 Detailed output
--dry-run                 Show scope without testing
--learning-mode           Educational explanations
```

## Understanding Results

### Severity Levels

- **CRITICAL**: Immediate security threat
- **HIGH**: Significant vulnerability
- **MEDIUM**: Important issue to address
- **LOW**: Minor concern
- **INFO**: Informational finding

### Confidence Levels

- **HIGH**: Strong indication of the issue
- **MEDIUM**: Reasonable likelihood
- **LOW**: Requires manual verification

## Troubleshooting

### Connection Refused

```
Error: Connection failed
```

Make sure your target server is running and listening on the specified port.

### Authorization Required

```
Error: Authorization required
```

Add `--authorized` flag or set `BARBAROSSA_AUTHORIZED=true`

### Too Many Findings

Reduce sensitivity:

```bash
barbarossa inspect ./src --verbose
```

Or focus on critical findings by severity in reports.

## Next Steps

1. **Read Security Documentation** - [SECURITY.md](../SECURITY.md)
2. **Learn About Authorization** - [authorization-and-scope.md](authorization-and-scope.md)
3. **Add Custom Rules** - [adding-custom-rules.md](adding-custom-rules.md)
4. **Run Tests** - `pytest`

## Getting Help

- Check documentation in `docs/`
- Review examples in `examples/`
- Read test cases in `tests/`
- Open an issue on GitHub
