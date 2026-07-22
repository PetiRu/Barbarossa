"""Tests for Python security rules."""

from barbarossa.inspect.python_rules import analyze_python_file


def test_detect_eval() -> None:
    """Test eval() detection."""
    code = "result = eval(user_input)"
    findings = list(analyze_python_file("test.py", code))
    assert any(f.id == "PYTHON_DANGEROUS_BUILTIN" for f in findings)


def test_detect_pickle() -> None:
    """Test pickle.loads() detection."""
    code = "data = pickle.loads(user_data)"
    findings = list(analyze_python_file("test.py", code))
    assert any(f.id == "PYTHON_INSECURE_DESERIALIZATION" for f in findings)


def test_detect_sql_formatting() -> None:
    """Test SQL string formatting detection."""
    code = "query = 'SELECT * FROM users WHERE id = %s' % user_id"
    findings = list(analyze_python_file("test.py", code))
    assert any(f.id == "PYTHON_SQL_INJECTION" for f in findings)


def test_detect_sql_f_string() -> None:
    """Test SQL injection detection in an f-string."""
    code = "query = f\"SELECT * FROM users WHERE name = '{username}'\""
    findings = list(analyze_python_file("test.py", code))
    assert any(f.id == "PYTHON_SQL_INJECTION" for f in findings)


def test_detect_sql_dot_format() -> None:
    """Test SQL injection detection with str.format()."""
    code = 'query = "DELETE FROM users WHERE id = {}".format(user_id)'
    findings = list(analyze_python_file("test.py", code))
    assert any(f.id == "PYTHON_SQL_INJECTION" for f in findings)


def test_detect_sql_concatenation() -> None:
    """Test SQL injection detection with concatenation."""
    code = 'query = "SELECT * FROM users WHERE name = " + username'
    findings = list(analyze_python_file("test.py", code))
    assert any(f.id == "PYTHON_SQL_INJECTION" for f in findings)


def test_detect_subprocess_shell() -> None:
    """Test subprocess with shell=True detection."""
    code = "subprocess.call(command, shell=True)"
    findings = list(analyze_python_file("test.py", code))
    assert any(f.id == "PYTHON_SHELL_INJECTION" for f in findings)


def test_safe_code() -> None:
    """Test safe code produces no findings."""
    code = """
import json
data = json.loads(input_data)
result = subprocess.run(['ls', '-la'], capture_output=True)
"""
    findings = list(analyze_python_file("test.py", code))
    assert len([f for f in findings if f.id.startswith("PYTHON_")]) == 0
