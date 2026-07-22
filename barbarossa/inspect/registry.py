"""Rule registry for inspection rules."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class InspectionRule:
    """Single inspection rule."""

    id: str
    title: str
    category: str
    description: str
    handler: Callable[..., Any]
    file_patterns: list[str]

    def __hash__(self) -> int:
        """Make rule hashable."""
        return hash(self.id)


class RuleRegistry:
    """Registry for inspection rules."""

    def __init__(self) -> None:
        """Initialize rule registry."""
        self.rules: dict[str, InspectionRule] = {}

    def register(
        self,
        id: str,
        title: str,
        category: str,
        description: str,
        file_patterns: list[str],
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to register a rule."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            rule = InspectionRule(
                id=id,
                title=title,
                category=category,
                description=description,
                handler=func,
                file_patterns=file_patterns,
            )
            self.rules[id] = rule
            return func

        return decorator

    def get_rules(self) -> list[InspectionRule]:
        """Get all registered rules."""
        return list(self.rules.values())

    def get_rules_for_file(self, file_path: str) -> list[InspectionRule]:
        """Get rules applicable to a file."""
        import fnmatch

        applicable = []
        for rule in self.rules.values():
            for pattern in rule.file_patterns:
                if fnmatch.fnmatch(file_path, pattern):
                    applicable.append(rule)
                    break
        return applicable
