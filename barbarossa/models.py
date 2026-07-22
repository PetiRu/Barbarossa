"""Data models for BARBAROSSA findings and scan results."""
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Self
class Severity(StrEnum):
    """Finding severity levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
class Confidence(StrEnum):
    """Finding confidence levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
class Category(StrEnum):
    """Finding categories."""
    SECRETS = "SECRETS"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    INJECTION = "INJECTION"
    UNSAFE_DESERIALIZATION = "UNSAFE_DESERIALIZATION"
    INSECURE_STORAGE = "INSECURE_STORAGE"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    MISCONFIGURATION = "MISCONFIGURATION"
    INSECURE_TRANSPORT = "INSECURE_TRANSPORT"
    FILE_UPLOAD = "FILE_UPLOAD"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    SESSION_MANAGEMENT = "SESSION_MANAGEMENT"
    UNSAFE_OPERATIONS = "UNSAFE_OPERATIONS"
@dataclass
class Finding:
    """A security finding from inspection or probes."""
    id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    file_path: str | None = None
    line_number: int | None = None
    endpoint: str | None = None
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    def __post_init__(self) -> None:
        """Validate finding after initialization."""
        if not self.id:
            raise ValueError("Finding ID cannot be empty")
        if not self.title:
            raise ValueError("Finding title cannot be empty")
    def __lt__(self, other: "Finding") -> bool:
        """Sort findings by severity, then confidence, then category."""
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                         Severity.LOW: 3, Severity.INFO: 4}
        confidence_order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        if severity_order[self.severity] != severity_order[other.severity]:
            return severity_order[self.severity] < severity_order[other.severity]
        if confidence_order[self.confidence] != confidence_order[other.confidence]:
            return confidence_order[self.confidence] < confidence_order[other.confidence]
        return self.category.value < other.category.value
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Create finding from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            category=Category(data["category"]),
            severity=Severity(data["severity"]),
            confidence=Confidence(data["confidence"]),
            description=data["description"],
            evidence=data["evidence"],
            file_path=data.get("file_path"),
            line_number=data.get("line_number"),
            endpoint=data.get("endpoint"),
            recommendation=data.get("recommendation", ""),
            references=data.get("references", []),
        )
@dataclass
class ScanResult:
    """Complete scan results."""
    start_time: datetime
    end_time: datetime | None = None
    target_url: str | None = None
    source_directory: str | None = None
    findings: list[Finding] = field(default_factory=list)
    total_requests: int = 0
    authorized: bool = False
    scan_stopped: bool = False
    def add_finding(self, finding: Finding) -> None:
        """Add a finding, deduplicating if needed."""
        existing = next((f for f in self.findings if self._findings_equal(f, finding)), None)
        if not existing:
            self.findings.append(finding)
    def _findings_equal(self, f1: Finding, f2: Finding) -> bool:
        """Check if two findings are equivalent."""
        return (f1.id == f2.id and
                f1.file_path == f2.file_path and
                f1.line_number == f2.line_number and
                f1.endpoint == f2.endpoint)
    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]
    def get_findings_by_category(self, category: Category) -> list[Finding]:
        """Get all findings of a specific category."""
        return [f for f in self.findings if f.category == category]
    @property
    def sorted_findings(self) -> list[Finding]:
        """Get findings sorted by severity and confidence."""
        return sorted(self.findings)
    @property
    def critical_findings(self) -> list[Finding]:
        """Get all critical findings."""
        return self.get_findings_by_severity(Severity.CRITICAL)
    @property
    def high_findings(self) -> list[Finding]:
        """Get all high-severity findings."""
        return self.get_findings_by_severity(Severity.HIGH)
    @property
    def duration_seconds(self) -> float:
        """Get scan duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    @classmethod
    def from_json(cls, json_str: str) -> Self:
        """Create scan result from JSON string."""
        data = json.loads(json_str)
        scan_info = data.get("scan_info", {})
        return cls(
            start_time=datetime.fromisoformat(scan_info["start_time"]),
            end_time=datetime.fromisoformat(scan_info["end_time"]) if scan_info.get("end_time") else None,
            target_url=data.get("target"),
            source_directory=data.get("source"),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            total_requests=data.get("summary", {}).get("total_requests", 0),
            authorized=scan_info.get("authorized", False),
            scan_stopped=scan_info.get("stopped", False),
        )
