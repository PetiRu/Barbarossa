"""Python-specific security rules."""

import ast
from typing import Generator
from barbarossa.models import Finding, Severity, Confidence, Category


def check_eval_usage(tree: ast.AST, file_path: str) -> Generator[Finding, None, None]:
    """Detect eval() and exec() usage."""
    dangerous_funcs = {"eval", "exec", "compile"}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in dangerous_funcs:
                yield Finding(
                    id="PYTHON_DANGEROUS_BUILTIN",
                    title=f"Use of dangerous {node.func.id}() function",
                    category=Category.UNSAFE_OPERATIONS,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"The {node.func.id}() function executes arbitrary Python code and is dangerous.",
                    evidence=node.func.id + "()",
                    file_path=file_path,
                    line_number=node.lineno,
                    recommendation=f"Replace {node.func.id}() with safer alternatives like ast.literal_eval() or json.loads().",
                    references=["https://owasp.org/www-community/Code_Injection"],
                )


def check_pickle_usage(tree: ast.AST, file_path: str) -> Generator[Finding, None, None]:
    """Detect pickle.loads() with untrusted data."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if (isinstance(node.func.value, ast.Name) and 
                    node.func.value.id == "pickle" and 
                    node.func.attr in ("loads", "load")):
                    yield Finding(
                        id="PYTHON_INSECURE_DESERIALIZATION",
                        title="Use of insecure pickle deserialization",
                        category=Category.UNSAFE_DESERIALIZATION,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description="pickle.loads() can execute arbitrary code. Never deserialize untrusted data.",
                        evidence=f"pickle.{node.func.attr}()",
                        file_path=file_path,
                        line_number=node.lineno,
                        recommendation="Use json.loads() for JSON data or prefer safer serialization formats.",
                        references=["https://owasp.org/www-community/Deserialization_of_untrusted_data"],
                    )


def check_sql_string_formatting(tree: ast.AST, file_path: str) -> Generator[Finding, None, None]:
    """Detect SQL queries with string formatting (SQL injection risk)."""
    for node in ast.walk(tree):
        # Check for string formatting operations on potential SQL strings
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                sql_keywords = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE")
                if any(kw in node.left.value.upper() for kw in sql_keywords):
                    yield Finding(
                        id="PYTHON_SQL_INJECTION",
                        title="Potential SQL injection via string formatting",
                        category=Category.INJECTION,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        description="SQL queries built with string formatting are vulnerable to injection.",
                        evidence="SQL string with % formatting",
                        file_path=file_path,
                        line_number=node.lineno,
                        recommendation="Use parameterized queries with ? or %s placeholders and pass parameters separately.",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    )


def check_subprocess_usage(tree: ast.AST, file_path: str) -> Generator[Finding, None, None]:
    """Detect subprocess calls with shell=True."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "subprocess" and node.func.attr in ("call", "run", "Popen"):
                        # Check for shell=True
                        for keyword in node.keywords:
                            if keyword.arg == "shell":
                                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                    yield Finding(
                                        id="PYTHON_SHELL_INJECTION",
                                        title="Subprocess call with shell=True",
                                        category=Category.INJECTION,
                                        severity=Severity.CRITICAL,
                                        confidence=Confidence.HIGH,
                                        description="shell=True allows command injection if input is unsanitized.",
                                        evidence="subprocess with shell=True",
                                        file_path=file_path,
                                        line_number=node.lineno,
                                        recommendation="Never use shell=True. Pass arguments as a list instead of a string.",
                                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                                    )


def analyze_python_file(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Analyze Python file for security issues."""
    try:
        tree = ast.parse(content)
        
        # Run all checks
        yield from check_eval_usage(tree, file_path)
        yield from check_pickle_usage(tree, file_path)
        yield from check_sql_string_formatting(tree, file_path)
        yield from check_subprocess_usage(tree, file_path)
        
    except SyntaxError:
        # Skip files with syntax errors
        pass
