"""Python-specific security rules."""

import ast
from collections.abc import Generator

from barbarossa.models import Category, Confidence, Finding, Severity


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
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "pickle"
                    and node.func.attr in ("loads", "load")
                ):
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
                        references=[
                            "https://owasp.org/www-community/Deserialization_of_untrusted_data"
                        ],
                    )


def check_sql_string_formatting(tree: ast.AST, file_path: str) -> Generator[Finding, None, None]:
    """Detect dynamic SQL built with f-strings, formatting, or concatenation."""
    sql_keywords = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE")

    def contains_sql(node: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and any(keyword in child.value.upper() for keyword in sql_keywords)
            for child in ast.walk(node)
        )

    for node in ast.walk(tree):
        dynamic_sql = False
        construction = "dynamic string construction"

        if isinstance(node, ast.JoinedStr) and contains_sql(node):
            dynamic_sql = any(isinstance(value, ast.FormattedValue) for value in node.values)
            construction = "f-string"
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            dynamic_sql = contains_sql(node)
            construction = "% formatting" if isinstance(node.op, ast.Mod) else "concatenation"
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and contains_sql(node.func.value)
        ):
            dynamic_sql = True
            construction = ".format()"

        if dynamic_sql:
            line_number = node.lineno if isinstance(node, ast.expr) else 1
            yield Finding(
                id="PYTHON_SQL_INJECTION",
                title="Potential SQL injection via dynamic query construction",
                category=Category.INJECTION,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="SQL queries built from dynamic strings may allow injection.",
                evidence=f"SQL string built with {construction}",
                file_path=file_path,
                line_number=line_number,
                recommendation=(
                    "Use parameterized queries and pass all values separately from the SQL text."
                ),
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            )


def check_subprocess_usage(tree: ast.AST, file_path: str) -> Generator[Finding, None, None]:
    """Detect subprocess calls with shell=True."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "subprocess" and node.func.attr in (
                        "call",
                        "run",
                        "Popen",
                    ):
                        # Check for shell=True
                        for keyword in node.keywords:
                            if keyword.arg == "shell":
                                if (
                                    isinstance(keyword.value, ast.Constant)
                                    and keyword.value.value is True
                                ):
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
                                        references=[
                                            "https://owasp.org/www-community/attacks/Command_Injection"
                                        ],
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
