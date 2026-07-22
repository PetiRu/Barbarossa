"""Security scanner for static code analysis."""

import logging
from pathlib import Path

from barbarossa.inspect.config_rules import check_docker_security, check_env_file, check_json_config
from barbarossa.inspect.javascript_rules import (
    detect_js_secrets,
    detect_js_unsafe_dom,
    detect_js_xss_patterns,
)
from barbarossa.inspect.python_rules import analyze_python_file
from barbarossa.inspect.secret_rules import detect_debug_mode, detect_secrets, detect_weak_crypto
from barbarossa.models import Finding

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Static security scanner for source code."""

    def __init__(self) -> None:
        """Initialize scanner."""
        self.findings: list[Finding] = []

    def scan_directory(self, directory: str) -> list[Finding]:
        """Scan directory for security issues."""
        path = Path(directory)

        if not path.exists():
            logger.error(f"Directory not found: {directory}")
            return []

        self.findings = []

        for file_path in path.rglob("*"):
            if file_path.is_file():
                self._scan_file(file_path)

        return self.findings

    def _scan_file(self, file_path: Path) -> None:
        """Scan individual file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            relative_path = str(file_path)

            # Python files
            if file_path.suffix == ".py":
                self.findings.extend(analyze_python_file(relative_path, content))
                self.findings.extend(detect_secrets(relative_path, content))
                self.findings.extend(detect_debug_mode(relative_path, content))

            # JavaScript/TypeScript files
            elif file_path.suffix in (".js", ".ts", ".jsx", ".tsx"):
                self.findings.extend(detect_js_secrets(relative_path, content))
                self.findings.extend(detect_js_unsafe_dom(relative_path, content))
                self.findings.extend(detect_js_xss_patterns(relative_path, content))

            # .env files
            elif file_path.name == ".env" or file_path.suffix == ".env":
                self.findings.extend(check_env_file(relative_path, content))

            # Dockerfile
            elif file_path.name == "Dockerfile" or file_path.name.startswith("Dockerfile."):
                self.findings.extend(check_docker_security(relative_path, content))

            # Docker Compose
            elif file_path.name in ("docker-compose.yml", "docker-compose.yaml"):
                from barbarossa.inspect.docker_rules import check_docker_compose_security
                self.findings.extend(check_docker_compose_security(relative_path, content))

            # JSON files
            elif file_path.suffix == ".json":
                self.findings.extend(check_json_config(relative_path, content))
                self.findings.extend(detect_secrets(relative_path, content))

            # All text files for secrets
            elif file_path.suffix in (".txt", ".conf", ".config", ".yaml", ".yml", ".toml", ".ini"):
                self.findings.extend(detect_secrets(relative_path, content))
                self.findings.extend(detect_weak_crypto(relative_path, content))

        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
