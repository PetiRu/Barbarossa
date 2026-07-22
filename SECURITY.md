# Security Policy

## Reporting a Vulnerability

**Do not** open a public GitHub issue if you discover a security vulnerability.

Instead, please email security@example.com with:

1. Description of the vulnerability
2. Steps to reproduce (if applicable)
3. Potential impact
4. Suggested fix (if you have one)

We will:

1. Acknowledge receipt within 48 hours
2. Investigate and confirm the vulnerability
3. Work on a fix in private
4. Credit you in the security advisory (unless you prefer anonymity)
5. Coordinate a public disclosure timeline

## Security Design

BARBAROSSA is designed with security-first principles:

* **Authorization-first**: Requires explicit scope and confirmation
* **Non-destructive**: Never modifies target systems
* **Deterministic**: No ML/LLM/probabilistic decisions
* **Scope-enforced**: Strict allowlist and DNS rebinding protection
* **Rate-limited**: Respects target resources
* **Auditable**: Full request logging

## Known Limitations

* Cannot exploit vulnerabilities (reporting only)
* No credential brute-forcing or password guessing
* Limited to authorized targets
* No evasion or stealth capabilities
* Static analysis based on patterns, not execution

## Responsible Use

BARBAROSSA is intended for:

* Testing systems you own
* Testing systems with explicit written permission
* Educational security learning
* Defensive security professionals
* Authorized penetration testing

BARBAROSSA is NOT intended for:

* Unauthorized testing of public websites
* Malicious purposes
* Illegal activities
* Bypassing authentication or authorization

Users are solely responsible for their use of BARBAROSSA and must comply with all applicable laws.
