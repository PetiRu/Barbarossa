"""Inspection module initialization."""

from barbarossa.inspect.scanner import SecurityScanner
from barbarossa.inspect.registry import RuleRegistry

__all__ = ["SecurityScanner", "RuleRegistry"]
