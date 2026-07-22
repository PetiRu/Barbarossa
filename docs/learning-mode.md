# Learning Mode

BARBAROSSA includes educational features for learning security testing.

## Enable Learning Mode

```bash
barbarossa probe http://localhost:8000 --learning-mode
```

## How It Works

For each test, BARBAROSSA:

1. **Explains** what the test checks
2. **Asks** you to predict the result
3. **Runs** the safe check
4. **Explains** the outcome
5. **Provides** remediation guidance

Example:

```
╔══════════════════════════════════════════════════════════════════╗
║ Test: Strict-Transport-Security Header                           ║
╚══════════════════════════════════════════════════════════════════╝

What this tests:
  The Strict-Transport-Security (HSTS) header forces the browser to
  always use HTTPS, preventing downgrade attacks.

Why it matters:
  Without HSTS, an attacker can intercept the first HTTP request
  and downgrade to plain HTTP, exposing the session.

What do you think? Will the target have this header?
  [y] Yes    [n] No    [skip] Skip this test
```

Then after running:

```
Result: ✗ Header is missing

This is a security weakness. The target does not force HTTPS.

How to fix it:
  Add to your web server configuration:
  
  Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## Exercises

BARBAROSSA can guide you through fixing issues in the demo app:

```bash
# Run vulnerable demo in learning mode
cd examples/vulnerable_demo_app
python app.py &

# In another terminal
barbarossa probe http://localhost:8000 \
  --learning-mode \
  --explain
```

## `--explain` Flag

Add beginner-friendly explanations to all findings:

```bash
barbarossa inspect ./src --explain
```

Findings include:

- What the vulnerability is
- Why it's dangerous
- How to fix it
- Common mistakes
- Best practices
