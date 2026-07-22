# Static Inspection Rules

## Overview

BARBAROSSA performs deterministic, pattern-based static analysis on source code without requiring compilation or execution.

## Supported File Types

- Python (`.py`)
- JavaScript (`.js`, `.jsx`)
- TypeScript (`.ts`, `.tsx`)
- JSON configuration files
- YAML (`*.yml`, `*.yaml`)
- TOML
- INI
- `.env` files
- Dockerfiles
- Docker Compose files
- HTML, CSS, text files

## Rule Categories

### Secrets Detection

Detects hardcoded credentials:

- AWS keys (`AKIA...`)
- Private keys (RSA, DSA, EC)
- API keys and tokens
- Database credentials
- JWT tokens
- GitHub tokens

Example finding:

```
Rule: SECRET_AWS_KEY
Title: Hardcoded AWS key found
File: config.py:42
Evidence: AKIA[16 chars]
Recommendation: Move to environment variable or secrets manager
```

### Weak Cryptography

- MD5, SHA1, DES usage
- Weak random number generation
- Deprecated crypto libraries

### Python-Specific Rules

- `eval()` and `exec()` usage
- Unsafe pickle deserialization
- SQL injection patterns
- Shell execution with untrusted input
- Subprocess with `shell=True`

### JavaScript/TypeScript Rules

- Hardcoded secrets in client code
- Unsafe DOM operations (innerHTML)
- XSS vulnerability indicators
- Use of deprecated libraries

### Configuration Issues

- Docker running as root
- Privileged containers
- Debug mode enabled in production
- Missing security headers
- Weak CORS configuration

## How to Read Findings

Each finding includes:

- **Rule ID**: Unique identifier (e.g., `PYTHON_SHELL_INJECTION`)
- **Title**: Human-readable summary
- **Category**: Type of issue (e.g., `INJECTION`)
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Confidence**: HIGH, MEDIUM, LOW
- **Description**: What the issue is
- **Evidence**: Code snippet or pattern found
- **Recommendation**: How to fix it
- **References**: Links to more information

## Example Report

```
🔴 [RED]Subprocess call with shell=True[/RED]
   Rule ID: PYTHON_SHELL_INJECTION
   Category: INJECTION
   Severity: CRITICAL | Confidence: HIGH
   File: app.py:15
   Description: shell=True allows command injection
   Evidence: subprocess with shell=True
   Recommendation: Pass args as list instead of string
   References: https://owasp.org/www-community/attacks/Command_Injection
```

## Limitations

- Pattern-based, not execution-based
- Cannot detect all vulnerabilities
- May have false positives
- Requires manual verification
- Configuration-dependent

## False Positives

Some findings may be false positives:

```python
# This may trigger SHELL_INJECTION warning:
# print("subprocess.run(['ls'], shell=True)")  # Just a comment!

# But this is the real issue:
subprocess.run(user_input, shell=True)  # Dangerous!
```

Always review findings in context.

## Customization

See [adding-custom-rules.md](adding-custom-rules.md) to add your own rules.
