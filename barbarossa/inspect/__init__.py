"""Inspection module initialization."""

from barbarossa.inspect.registry import RuleRegistry
from barbarossa.inspect.scanner import SecurityScanner

__all__ = ["SecurityScanner", "RuleRegistry"]
