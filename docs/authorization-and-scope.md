# Authorization and Scope

## Safety First

BARBAROSSA enforces strict authorization requirements by default to prevent unauthorized testing.

## Target Scope

### Allowed by Default

These targets do NOT require authorization:

- **Localhost**: `localhost`, `127.0.0.1`, `::1`
- **Private IPs** (RFC1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Loopback**: `127.0.0.0/8`, `::1/128`

### Blocked by Default

These targets are ALWAYS blocked:

- **Cloud Metadata**: `169.254.169.254`, `metadata.google.internal`, etc.
- **Reserved IPs**: `0.0.0.0`, `255.255.255.255`, etc.
- **Link-Local**: `169.254.0.0/16`
- **Multicast**: `224.0.0.0/4`
- **Public Domains** (not in allowlist)

## Authorization Requirements

### Interactive Mode

When scanning public domains, you must provide explicit authorization:

```bash
barbarossa probe https://example.com
```

You will be prompted:

```
⚠️  AUTHORIZATION REQUIRED
   Target: https://example.com

You must confirm ownership or explicit authorization to test this target.
Unauthorized security testing may be illegal.

Enter 'I AM AUTHORIZED' to continue:
```

### Command-Line Flag

```bash
barbarossa probe https://example.com --authorized
```

This confirms you have authorization (but doesn't bypass the allowlist).

### Environment Variable

For CI/CD pipelines:

```bash
export BARBAROSSA_AUTHORIZED=true
barbarossa probe http://localhost:8000
```

**Important**: The environment variable does NOT bypass the allowlist. Public domains must still be explicitly allowed.

## Allowlist Configuration

### Add Domains

```bash
barbarossa probe https://example.com \
  --authorized \
  --allowlist example.com \
  --allowlist www.example.com \
  --allowlist api.example.com
```

### Configuration File

`config.toml`:

```toml
[scan]
authorized_targets = [
    "localhost",
    "127.0.0.1",
    "example.com",
    "api.example.com",
]
```

Then:

```bash
barbarossa scan --config config.toml --authorized
```

## Redirect Validation

BARBAROSSA follows redirects only if they stay in scope:

```
http://example.com/page1 (✓ allowed)
  ↓ redirect
http://example.com/page2 (✓ same domain - allowed)
  ↓ redirect
http://attacker.com/steal (✗ BLOCKED - different domain)
```

The tool will refuse to follow redirects outside the authorized scope.

## DNS Rebinding Protection

BARBAROSSA validates DNS resolution to prevent DNS rebinding attacks:

1. Resolves hostname to IP
2. Checks IP is not blocked/reserved
3. Validates against scope
4. Proceeds with request

Example block:

```
$ barbarossa probe http://rebind.example.com --authorized
Error: Resolved to 169.254.169.254 (blocked cloud metadata IP)
```

## CI/CD Integration

For automated security scanning in CI/CD:

```yaml
# GitHub Actions example
- name: BARBAROSSA Scan
  env:
    BARBAROSSA_AUTHORIZED: true
  run: |
    barbarossa scan \
      --source . \
      --target http://localhost:8000 \
      --format sarif \
      --output .
```

The allowlist is still enforced - CI still can only scan authorized targets.

## Rate Limiting

To protect target systems, BARBAROSSA enforces rate limits:

- **2 requests/second** (default)
- **150 total requests** (default)
- **10 second timeout** (default)
- **3 consecutive errors** before pausing

Customize:

```bash
barbarossa probe http://localhost:8000 \
  --authorized \
  --requests-per-second 1 \
  --max-requests 50 \
  --timeout 20
```

## Emergency Stop

Create a file to stop all active scans:

```bash
touch STOP_BARBAROSSA
```

All running probes will stop immediately and cleanly shutdown.

## Security Model

BARBAROSSA uses **defense in depth**:

1. **Authorization required** - User must confirm
2. **Scope validation** - Checks target is allowed
3. **DNS validation** - Prevents DNS rebinding
4. **Redirect validation** - Follows only in-scope redirects
5. **Rate limiting** - Protects target systems
6. **Request logging** - Full audit trail

## Responsible Use

Remember:

- **You are responsible** for your use of BARBAROSSA
- **Unauthorized testing is illegal** in most jurisdictions
- **Get written permission** before testing
- **Use only on systems you own** or have permission to test
- **Follow local laws and regulations**

See [SECURITY.md](../SECURITY.md) for full security policy.
