# Adding Custom Rules

You can extend BARBAROSSA with custom inspection rules.

## Rule Structure

All rules follow this pattern:

```python
from barbarossa.models import Finding, Severity, Confidence, Category

def detect_my_issue(file_path: str, content: str):
    """Detect my custom security issue."""
    if "bad_pattern" in content:
        yield Finding(
            id="MY_RULE_ID",
            title="Title of the issue",
            category=Category.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="What the issue is and why it matters",
            evidence="bad_pattern",
            file_path=file_path,
            line_number=1,
            recommendation="How to fix it",
            references=["https://example.com"],
        )
```

## Example: Detect TODO Comments

```python
import re
from typing import Generator
from barbarossa.models import Finding, Severity, Confidence, Category

def detect_todos(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Detect TODO comments (code quality indicator)."""
    for match in re.finditer(r'#\s*TODO', content):
        line_num = content[:match.start()].count('\n') + 1
        yield Finding(
            id="CODE_TODO",
            title="TODO comment found",
            category=Category.MISCONFIGURATION,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            description="Code contains unfinished TODO comment",
            evidence="# TODO",
            file_path=file_path,
            line_number=line_num,
            recommendation="Resolve or remove TODO before shipping",
            references=[],
        )
```

## Adding Your Rule

1. Add function to appropriate module:
   - `barbarossa/inspect/python_rules.py` - Python rules
   - `barbarossa/inspect/javascript_rules.py` - JS/TS rules
   - `barbarossa/inspect/config_rules.py` - Config files
   - `barbarossa/inspect/secret_rules.py` - Secrets/credentials

2. Call your function from `scanner.py`:

```python
# In barbarossa/inspect/scanner.py
elif file_path.suffix == ".py":
    # ... existing calls ...
    self.findings.extend(detect_todos(relative_path, content))
```

3. Add tests in `tests/`:

```python
def test_detect_todos():
    code = "# TODO: fix this vulnerability"
    findings = list(detect_todos("test.py", code))
    assert any(f.id == "CODE_TODO" for f in findings)
```

4. Run tests:

```bash
pytest tests/test_my_rule.py
```

## Best Practices

1. **Be Specific**: Avoid false positives
   ```python
   # Bad: too broad
   if "sql" in content.lower():
       yield Finding(...)
   
   # Good: specific pattern
   if "SELECT * FROM" in content.upper():
       yield Finding(...)
   ```

2. **Provide Evidence**: Show what was found
   ```python
   evidence=match.group(0)[:100]  # Show actual match
   ```

3. **Include Line Numbers**: Help developers locate issue
   ```python
   line_num = content[:match.start()].count('\n') + 1
   ```

4. **Set Appropriate Severity**: Don't over-alarm
   - CRITICAL: Remote code execution, auth bypass
   - HIGH: Injection, XSS, CSRF
   - MEDIUM: Missing headers, weak crypto
   - LOW: Code quality, best practices
   - INFO: Informational findings

5. **Add References**: Link to resources
   ```python
   references=[
       "https://owasp.org/www-community/attacks/SQL_Injection",
       "https://cwe.mitre.org/data/definitions/89.html",
   ]
   ```

6. **Test Thoroughly**: Cover edge cases
   ```python
   # Test positive case
   assert detect_issue(code_with_issue)
   
   # Test negative case
   assert not detect_issue(safe_code)
   
   # Test edge cases
   assert not detect_issue(commented_issue)
   ```

## Testing Custom Rules

```bash
# Run just your tests
pytest tests/test_my_rule.py -v

# Run with coverage
pytest tests/test_my_rule.py --cov=barbarossa

# Run all tests
pytest
```

## Performance Considerations

- Use compiled regex patterns for speed
- Limit to necessary file types
- Skip large files
- Use generators (yield) not lists
