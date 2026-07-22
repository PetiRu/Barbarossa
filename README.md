# BARBAROSSA

Inspect. Probe. Fortify.

**BARBAROSSA** is a deterministic, non-destructive web application security inspection and authorized testing toolkit for developers, students, website owners, and defensive security professionals.

## ⚠️ IMPORTANT DISCLAIMER

**Use BARBAROSSA only on systems you own or are explicitly authorized to test.**

Unauthorized security testing may be illegal. BARBAROSSA enforces strict authorization requirements by default.

## Features

### Stage 1: Static Inspection (INSPECT)

Analyze source code for security vulnerabilities using deterministic rules:

- **Python** - AST-based analysis for dangerous patterns
- **JavaScript/TypeScript** - Pattern-based code inspection
- **Configuration Files** - JSON, YAML, TOML, INI, .env, Dockerfile
- **Secret Detection** - Credentials, API keys, tokens, private keys
- **Common Issues** - SQL injection indicators, unsafe deserialization, weak hashing, CORS misconfig

### Stage 2: Active Probes (PROBE)

Non-destructive HTTP security checks on authorized targets:

- **HTTPS & Redirects** - TLS configuration and HTTP→HTTPS enforcement
- **Security Headers** - CSP, HSTS, X-Content-Type-Options, etc.
- **Cookies & Auth** - Secure flags, HttpOnly, SameSite, CSRF tokens
- **Input Reflection** - Harmless XSS/SQL injection indicators
- **Common Issues** - Directory listing, exposed files, verbose errors
- **Rate-Limited** - 2 req/sec, 150 total, 10s timeout (configurable)

### Reporting

Generate professional reports in multiple formats:

- **Console** - Real-time findings with color and formatting
- **JSON** - Structured data for integration
- **HTML** - Beautiful, shareable reports with charts
- **SARIF** - GitHub-compatible security format

### Learning Mode

Educational mode for security students:

- Explain what each test does
- Ask learner to predict the result
- Run the safe check
- Explain the outcome
- Provide remediation exercises

## Security Design

✅ **Deterministic** - No ML, LLMs, or probabilistic algorithms  
✅ **Non-destructive** - Never modifies target systems  
✅ **Authorization-first** - Requires explicit scope and consent  
✅ **Scope-enforced** - Strict allowlist, blocks cloud metadata, DNS rebinding  
✅ **Rate-limited** - Respects target resources  
✅ **Emergency-stop** - `STOP_BARBAROSSA` file halts all scans  
✅ **Auditable** - Full request logging and redacted reports  

## Installation

### Requirements

- Python 3.12+
- pip or uv

### From Source

```bash
git clone https://github.com/PetiRu/Barbarossa.git
cd Barbarossa
pip install -e .
```

### Development

```bash
pip install -e ".[dev]"
ruff check .
mypy barbarossa
pytest
```

## Quick Start

### 1. Run Static Inspection

Scan your source code:

```bash
barbarossa inspect ./my-website
```

### 2. Start the Vulnerable Demo

```bash
cd examples/vulnerable_demo_app
python app.py
```

In another terminal:

```bash
barbarossa probe http://127.0.0.1:8000 --authorized
```

### 3. Run Complete Scan

```bash
barbarossa scan \
  --source ./my-website \
  --target http://127.0.0.1:8000 \
  --authorized \
  --format console,json,html
```

### 4. Use Configuration File

Create `config.toml`:

```toml
[scan]
target_url = "http://127.0.0.1:8000"
source_directory = "./my-website"
authorized_targets = ["localhost", "127.0.0.1"]

[security]
requests_per_second = 2
max_requests = 150
request_timeout = 10
max_redirects = 3

[output]
formats = ["console", "json", "html", "sarif"]
```

Run:

```bash
barbarossa scan --config config.toml --authorized
```

## Commands

```bash
# Static inspection only
barbarossa inspect ./source-dir

# Active probes only
barbarossa probe http://localhost:8000

# Complete scan (both stages)
barbarossa scan --source ./src --target http://localhost:8000

# With custom options
barbarossa scan \
  --source ./src \
  --target http://localhost:8000 \
  --authorized \
  --requests-per-second 3 \
  --max-requests 200 \
  --format console,html,json \
  --output reports/

# Learning mode
barbarossa probe http://localhost:8000 --learning-mode

# Dry run (show scope without testing)
barbarossa scan --config config.toml --dry-run

# Explain findings
barbarossa inspect ./src --explain

# Verbose output
barbarossa scan --config config.toml --verbose
```

## Full Option Reference

```bash
barbarossa [COMMAND] [OPTIONS]

Commands:
  inspect    Static code analysis
  probe      Active HTTP security checks
  scan       Complete inspection + probes

Global Options:
  --source DIR              Source directory for static inspection
  --target URL              Target URL for active probes
  --config FILE             Configuration file (TOML)
  --authorized              Confirm authorization for this target
  --allowlist DOMAIN        Add domain to allowlist (repeatable)
  --requests-per-second N   Rate limit (default: 2)
  --max-requests N          Maximum requests (default: 150)
  --timeout SECONDS         Request timeout (default: 10)
  --format FORMAT           Output format: console,json,html,sarif
  --output DIR              Output directory (default: ./reports/)
  --learning-mode           Educational mode with explanations
  --explain                 Add beginner-friendly explanations
  --verbose                 Verbose logging
  --dry-run                 Show scope without testing
  --help                    Show help
```

## Examples

### Test Your Local Website

```bash
# Start your development server
python -m http.server 8000

# In another terminal
barbarossa scan \
  --source . \
  --target http://127.0.0.1:8000 \
  --authorized \
  --format console,html
```

Reports are saved to `reports/barbarossa-report.*`

### Add Public Domains to Allowlist

Only required for public domains (localhost/private IPs allowed by default):

```bash
barbarossa probe https://example.com \
  --authorized \
  --allowlist example.com \
  --allowlist www.example.com
```

### CI/CD Integration

```bash
# In your GitHub Actions or CI
barbarossa scan \
  --source . \
  --target http://localhost:8000 \
  --authorized \
  --format sarif \
  --output .

# Results available in barbarossa-report.sarif
```

Env var bypass (still respects allowlist):

```bash
export BARBAROSSA_AUTHORIZED=true
barbarossa probe http://localhost:8000
```

## Documentation

Detailed documentation in `docs/`:

- **[Getting Started](docs/getting-started.md)** - Installation and first scan
- **[Authorization and Scope](docs/authorization-and-scope.md)** - Security model
- **[Static Inspection](docs/static-inspection.md)** - Code analysis rules
- **[Active Probes](docs/active-probes.md)** - HTTP checks
- **[Reports](docs/reports.md)** - Output formats
- **[Learning Mode](docs/learning-mode.md)** - Educational features
- **[Adding Custom Rules](docs/adding-custom-rules.md)** - Extend BARBAROSSA

## Limitations

⚠️ **BARBAROSSA reports security indicators and potential weaknesses.**  
**A finding does not automatically prove exploitability.**  
**Manual verification is required.**

- No automated exploitation
- No payload execution
- No password brute-forcing
- No data exfiltration
- No DoS/flooding
- No evasion techniques
- No authentication bypass
- No remote code execution

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - See [LICENSE](LICENSE) file.

## Code of Conduct

Please see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security Policy

See [SECURITY.md](SECURITY.md) for reporting security issues.

---

Built with ❤️ for defensive security professionals and developers.
