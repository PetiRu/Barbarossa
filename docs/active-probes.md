# Active Probes

## Overview

BARBAROSSA performs non-destructive HTTP security checks on running web applications.

## Safe Testing Methodology

All probes are designed to be safe and non-destructive:

- No payloads that could be executed
- Harmless testing values only
- No modifications to target data
- Respects rate limits
- Stops after the configured number of consecutive request failures

## Probe Categories

### HTTPS & Transport Security

- HTTPS availability
- HTTP → HTTPS redirection
- TLS certificate validation
- HSTS header presence

### Security Headers

Checks for missing or weak:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

### Information Disclosure

- Server version headers
- Directory listing
- Common debug and configuration endpoints

### Common Exposed Files

Safe probes for publicly known sensitive files:

- `/.git/config`
- `/.env`
- `/robots.txt`
- `/sitemap.xml`
- `/.well-known/security.txt`
- `/debug`
- `/admin`
- `/config`

## Rate Limiting

Default safe values:

```
2 requests/second
150 total requests
10 second timeout
3 consecutive errors before pause
```

Customize with options:

```bash
barbarossa probe http://localhost:8000 \
  --requests-per-second 1 \
  --max-requests 100 \
  --timeout 15
```

## Example Output

```
 Probing: http://localhost:8000
 Found issues:

[red]●[/red] Missing Strict-Transport-Security Header
   Rule: MISSING_HSTS
   Severity: HIGH | Confidence: HIGH
   Endpoint: http://localhost:8000/
   Recommendation: Add HSTS header with max-age

[yellow]●[/yellow] Weak CSP with unsafe-inline
   Rule: WEAK_CSP
   Severity: HIGH
   Endpoint: http://localhost:8000/
   Recommendation: Remove unsafe-inline from CSP

[blue]●[/blue] Missing X-Frame-Options Header
   Rule: MISSING_XFRAMEOPTIONS
   Severity: MEDIUM
   Endpoint: http://localhost:8000/
   Recommendation: Set to DENY or SAMEORIGIN
```

## What BARBAROSSA Does NOT Do

- Execute JavaScript or payloads
- Brute-force credentials
- Exploit vulnerabilities
- Modify server data
- Create accounts
- Bypass authentication
- Enumerate hidden files exhaustively
- Perform fuzzing or flooding

## Redirect Following

BARBAROSSA safely follows redirects:

- Limits to 3 redirects by default
- Validates each redirect target
- Blocks cross-scope redirects
- Prevents redirect loops

## Error Handling

If too many consecutive errors occur, scanning stops:

```
3 consecutive request errors → Stop
Check your rate limits
```

## Performance

Typical scan duration:

- 11 base requests, plus GET fallbacks when a server rejects HEAD
- 2 req/sec rate limit
- Usually under 15 seconds on a responsive local target

Adjust with `--requests-per-second` if needed.

## Integration with Reports

Probe findings appear in all report formats:

- Console (real-time)
- JSON (structured)
- HTML (visual)
- SARIF (GitHub)
