"""Docker security rules."""

from collections.abc import Generator

from barbarossa.models import Category, Confidence, Finding, Severity


def check_docker_compose_security(file_path: str, content: str) -> Generator[Finding, None, None]:
    """Check Docker Compose files for security issues."""

    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # Check for privileged containers
        if "privileged:" in stripped and "true" in stripped.lower():
            yield Finding(
                id="DOCKER_PRIVILEGED",
                title="Privileged container in Docker Compose",
                category=Category.MISCONFIGURATION,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description="Running containers in privileged mode grants excessive capabilities.",
                evidence="privileged: true",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use cap_add instead of privileged mode to add only needed capabilities.",
                references=["https://docs.docker.com/engine/reference/run/"],
            )

        # Check for exposed ports
        if "ports:" in stripped:
            # Look at next lines for port mappings
            for i in range(line_num, min(line_num + 5, len(lines))):
                port_line = lines[i].strip()
                if ":" in port_line and not port_line.startswith("#"):
                    # Check for privileged ports
                    if any(port_line.startswith(str(p)) for p in range(1, 1024)):
                        yield Finding(
                            id="DOCKER_PRIVILEGED_PORT",
                            title="Container exposes privileged port",
                            category=Category.MISCONFIGURATION,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            description="Container exposes a privileged port (< 1024).",
                            evidence=port_line,
                            file_path=file_path,
                            line_number=i + 1,
                            recommendation="Map to high-numbered ports (> 1024) and use reverse proxy if needed.",
                            references=[
                                "https://www.iana.org/assignments/service-names-port-numbers/"
                            ],
                        )
