"""Configuration file security rules."""

import json
from collections.abc import Generator
from typing import Any

from barbarossa.models import Category, Confidence, Finding, Severity


def check_env_file(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Check .env files for secrets."""

    # Parse .env file
    for line_num, line in enumerate(content.split("\n"), 1):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # Check for key=value pairs with secrets
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip().upper()
            value = value.strip()

            # Check for sensitive keys
            sensitive_keys = ["PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "API"]
            if any(sk in key for sk in sensitive_keys):
                # Check if value is not already a placeholder
                if not value.startswith(("${", "{{", "CHANGE_ME", "TODO", "PLACEHOLDER", "YOUR_")):
                    yield Finding(
                        id="CONFIG_HARDCODED_SECRET",
                        title="Hardcoded secret in .env file",
                        category=Category.SECRETS,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        description=f"Potential secret in .env file: {key}",
                        evidence=f"{key}=***",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Remove actual secrets from .env files. Use .env.example with placeholders.",
                        references=["https://owasp.org/www-community/Sensitive_Data_Exposure"],
                    )


def check_docker_security(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Check Dockerfile for security issues."""

    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # Check for running as root
        if "USER root" in stripped or (stripped.startswith("RUN") and "rm -rf /" in stripped):
            yield Finding(
                id="DOCKER_RUNS_AS_ROOT",
                title="Docker container may run as root",
                category=Category.MISCONFIGURATION,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="Containers should run with minimal privileges, not as root.",
                evidence=stripped,
                file_path=file_path,
                line_number=line_num,
                recommendation="Use 'USER appuser' to run container as non-root user.",
                references=["https://owasp.org/www-community/Privilege_Escalation"],
            )

        # Check for secrets in ENV
        if "ENV" in stripped and any(k in stripped.upper() for k in ["PASSWORD", "SECRET", "KEY", "TOKEN"]):
            yield Finding(
                id="DOCKER_HARDCODED_SECRET",
                title="Hardcoded secret in Dockerfile",
                category=Category.SECRETS,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Secrets should not be hardcoded in Dockerfile.",
                evidence="ENV with secret",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use Docker secrets or build arguments instead of hardcoded values.",
                references=["https://docs.docker.com/engine/swarm/secrets/"],
            )


def check_json_config(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Check JSON configuration files."""

    try:
        config = json.loads(content)
    except json.JSONDecodeError:
        return

    def check_dict(obj: dict[str, Any], path: str = "") -> Generator[Finding, None, None]:
        """Recursively check dictionary."""
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key

            # Check for sensitive values
            if isinstance(key, str):
                if any(k in key.lower() for k in ["password", "secret", "token", "key", "credential"]):
                    if isinstance(value, str) and len(value) > 5:
                        yield Finding(
                            id="JSON_HARDCODED_SECRET",
                            title="Hardcoded secret in JSON configuration",
                            category=Category.SECRETS,
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            description=f"Potential secret found: {current_path}",
                            evidence=f"{current_path}: ***",
                            file_path=file_path,
                            recommendation="Move secrets to environment variables or secure secret management.",
                            references=["https://owasp.org/www-community/Sensitive_Data_Exposure"],
                        )

            # Recurse into nested objects
            if isinstance(value, dict):
                yield from check_dict(value, current_path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        yield from check_dict(item, f"{current_path}[{i}]")

    yield from check_dict(config)
