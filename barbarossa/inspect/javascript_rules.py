"""JavaScript/TypeScript security rules."""

import re
from collections.abc import Generator

from barbarossa.models import Category, Confidence, Finding, Severity


def detect_js_secrets(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Detect secrets in JavaScript/TypeScript."""

    patterns = {
        "API_KEY": r"(?:apiKey|api_key|API_KEY)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{20,})['\"]",
        "PRIVATE_KEY": r"-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----",
        "PASSWORD": r"(?:password|pwd)\s*[:=]\s*['\"]([^\s'\"]{5,})['\"]",
        "JWT": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    }

    for pattern_name, pattern in patterns.items():
        for match_obj in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[: match_obj.start()].count("\n") + 1

            yield Finding(
                id=f"JS_SECRET_{pattern_name}",
                title=f"Hardcoded secret in JavaScript: {pattern_name}",
                category=Category.SECRETS,
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                description="Secrets hardcoded in JavaScript can be exposed in browser DevTools or source maps.",
                evidence=match_obj.group(0)[:30],
                file_path=file_path,
                line_number=line_num,
                recommendation="Move secrets to backend or environment variables. Never hardcode in client-side code.",
                references=["https://owasp.org/www-community/Sensitive_Data_Exposure"],
            )


def detect_js_unsafe_dom(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Detect unsafe DOM operations in JavaScript."""

    unsafe_methods = {
        "innerHTML": r"\.innerHTML\s*=",
        "outerHTML": r"\.outerHTML\s*=",
        "eval": r"\beval\s*\(",
        "Function": r"\bnew\s+Function\s*\(",
    }

    for method, pattern in unsafe_methods.items():
        for match_obj in re.finditer(pattern, content):
            line_num = content[: match_obj.start()].count("\n") + 1

            yield Finding(
                id=f"JS_UNSAFE_{method.upper()}",
                title=f"Unsafe use of {method} in JavaScript",
                category=Category.INJECTION,
                severity=Severity.HIGH if method != "eval" else Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                description=f"{method} with untrusted input can lead to XSS attacks.",
                evidence=match_obj.group(0),
                file_path=file_path,
                line_number=line_num,
                recommendation=f"Use textContent instead of {method}, or sanitize/escape input with DOMPurify.",
                references=["https://owasp.org/www-community/attacks/xss/"],
            )


def detect_js_dangerous_libs(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Detect use of dangerous libraries in JavaScript."""

    dangerous = {
        "moment": "Use modern date library like date-fns or Day.js",
        "underscore": "Use lodash instead, or use native Array methods",
    }

    for lib, recommendation in dangerous.items():
        if re.search(rf"import.*from\s+['\"]({lib})['\"]", content) or re.search(
            rf"require\s*\(\s*['\"]({lib})['\"]", content
        ):
            line_num = 1
            match = re.search(rf"({lib})", content)
            if match:
                line_num = content[: match.start()].count("\n") + 1

            yield Finding(
                id=f"JS_LIB_{lib.upper()}",
                title=f"Use of {lib} library",
                category=Category.MISCONFIGURATION,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=f"The {lib} library may have performance or maintenance issues.",
                evidence=lib,
                file_path=file_path,
                line_number=line_num,
                recommendation=recommendation,
                references=[f"https://www.npmjs.com/package/{lib}"],
            )


def detect_js_xss_patterns(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Detect potential XSS patterns in JavaScript."""

    xss_patterns = {
        "user_input_to_dom": r"document\.write\s*\(\s*(?:req\.|params\.|query\.)",
        "unescaped_template": r"\$\{.*\}.*?innerHTML",
    }

    for pattern_name, pattern in xss_patterns.items():
        for match_obj in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[: match_obj.start()].count("\n") + 1

            yield Finding(
                id=f"JS_XSS_{pattern_name.upper()}",
                title=f"Potential XSS vulnerability: {pattern_name}",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                description="User input is being rendered to DOM without sanitization.",
                evidence=match_obj.group(0)[:50],
                file_path=file_path,
                line_number=line_num,
                recommendation="Use textContent instead of innerHTML or sanitize input with DOMPurify.",
                references=["https://owasp.org/www-community/attacks/xss/"],
            )
