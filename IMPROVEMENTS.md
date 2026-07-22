# BARBAROSSA Roadmap

This roadmap reflects the implemented code. A checked item must be covered by an automated test
or a reproducible release check before it is considered complete.

## v0.1.1 — Core reliability

- [x] Package every `barbarossa.*` subpackage in the wheel.
- [x] Run the CLI from the installed wheel, not only an editable checkout.
- [x] Load source, target, scope, limits, features, and report settings from TOML.
- [x] Keep authorization confirmation separate from scope validation.
- [x] Validate and pin all resolved IP addresses before outbound requests.
- [x] Revalidate each redirect host, port, scheme, and resolved address.
- [x] Escape HTML report data and redact evidence and sensitive URL fields.
- [x] Implement `STOP_BARBAROSSA` for static and active scans.
- [x] Repair the Docker demo dependency, health, port, and startup flow.
- [x] Detect dynamic Python SQL built with f-strings, `%`, `.format()`, or concatenation.
- [x] Fall back to GET when an exposed-file endpoint rejects HEAD with HTTP 405.

## v0.2 — Detection quality

- [ ] Add lightweight source-to-sink data-flow analysis for SQL and command execution.
- [ ] Resolve import aliases in Python AST rules.
- [ ] Add finding fingerprints and deterministic deduplication across scan stages.
- [ ] Attach CWE and OWASP identifiers to every rule.
- [ ] Add repository ignore rules, binary detection, and configurable file-size limits.
- [ ] Add explicit cookie, CORS, and CSRF checks only after each check has fixtures and tests.
- [ ] Benchmark precision and recall on intentionally vulnerable and secure fixture projects.

## v0.3 — CI and release engineering

- [x] Test supported Python versions in GitHub Actions.
- [x] Gate pull requests on Ruff, MyPy, pytest, and coverage.
- [x] Build and install the wheel in CI, then run a CLI smoke test.
- [x] Build both Docker demo services in CI.
- [ ] Upload SARIF from an authorized, isolated fixture scan.
- [ ] Add Dependabot and documented branch-protection settings.
- [ ] Publish signed release artifacts and a changelog.

## v1.0 — Stable defensive toolkit

- [ ] Freeze and document the rule API and report schema.
- [ ] Add scan profiles with schema validation and migration support.
- [ ] Add a local REST API only after the CLI and report schema are stable.
- [ ] Add a local dashboard only after the API has authorization, cancellation, and audit tests.

BARBAROSSA remains deterministic and non-destructive. AI/ML detection, exploitation, brute force,
stealth, denial-of-service behavior, and automatic remediation are outside the project scope.
