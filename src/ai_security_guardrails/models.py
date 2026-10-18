from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Violation:
    rule_id: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    action: str
    role: str
    requested_tools: tuple[str, ...] = field(default_factory=tuple)
    violations: tuple[Violation, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "role": self.role,
            "requested_tools": list(self.requested_tools),
            "violations": [violation.to_dict() for violation in self.violations],
        }


@dataclass(frozen=True)
class RedactionResult:
    text: str
    findings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {"text": self.text, "findings": list(self.findings)}
