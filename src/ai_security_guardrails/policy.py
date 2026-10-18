from __future__ import annotations

import re
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Decision, RedactionResult, Violation


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: str = "high"
    message: str = "Policy rule matched."
    replacement: str | None = None


class PolicyEngine:
    def __init__(self, policy: dict[str, Any]) -> None:
        limits = policy.get("limits", {})
        self.max_prompt_chars = int(limits.get("max_prompt_chars", 4000))
        self.max_tools_per_request = int(limits.get("max_tools_per_request", 3))
        self.roles = {
            str(role): frozenset(str(tool) for tool in tools)
            for role, tools in policy.get("roles", {}).items()
        }
        self.blocked_tools = frozenset(
            str(tool) for tool in policy.get("blocked_tools", {}).get("names", [])
        )
        self.input_rules = tuple(self._load_input_rule(item) for item in policy.get("input_rules", []))
        self.output_rules = tuple(
            self._load_output_rule(item) for item in policy.get("output_rules", [])
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        with Path(path).open("rb") as policy_file:
            return cls(tomllib.load(policy_file))

    @staticmethod
    def _load_input_rule(item: dict[str, Any]) -> PatternRule:
        return PatternRule(
            rule_id=str(item["id"]),
            pattern=re.compile(str(item["pattern"])),
            severity=str(item.get("severity", "high")),
            message=str(item.get("message", "Input policy rule matched.")),
        )

    @staticmethod
    def _load_output_rule(item: dict[str, Any]) -> PatternRule:
        return PatternRule(
            rule_id=str(item["id"]),
            pattern=re.compile(str(item["pattern"])),
            replacement=str(item.get("replacement", "[REDACTED]")),
        )

    @staticmethod
    def _normalize(text: str) -> str:
        normalized = unicodedata.normalize("NFKC", text)
        return " ".join(normalized.split())

    def evaluate(self, prompt: str, role: str, requested_tools: list[str] | tuple[str, ...]) -> Decision:
        normalized_prompt = self._normalize(prompt)
        normalized_tools = tuple(sorted(set(str(tool).strip() for tool in requested_tools if tool)))
        violations: list[Violation] = []

        if len(prompt) > self.max_prompt_chars:
            violations.append(
                Violation(
                    "input.prompt-too-long",
                    "medium",
                    f"Prompt exceeds the {self.max_prompt_chars}-character limit.",
                )
            )

        if role not in self.roles:
            violations.append(Violation("identity.unknown-role", "high", "Caller role is not defined."))
            allowed_tools: frozenset[str] = frozenset()
        else:
            allowed_tools = self.roles[role]

        if len(normalized_tools) > self.max_tools_per_request:
            violations.append(
                Violation(
                    "tool.too-many-requests",
                    "high",
                    f"Request exceeds the {self.max_tools_per_request}-tool limit.",
                )
            )

        for tool in normalized_tools:
            if tool in self.blocked_tools:
                violations.append(
                    Violation("tool.explicitly-blocked", "critical", f'Tool "{tool}" is always blocked.')
                )
            elif tool not in allowed_tools:
                violations.append(
                    Violation(
                        "tool.not-authorized",
                        "high",
                        f'Role "{role}" is not authorized to use "{tool}".',
                    )
                )

        for rule in self.input_rules:
            if rule.pattern.search(normalized_prompt):
                violations.append(Violation(rule.rule_id, rule.severity, rule.message))

        unique_violations = tuple(
            {violation.rule_id: violation for violation in violations}.values()
        )
        allowed = not unique_violations
        return Decision(
            allowed=allowed,
            action="allow" if allowed else "block",
            role=role,
            requested_tools=normalized_tools,
            violations=unique_violations,
        )

    def redact(self, text: str) -> RedactionResult:
        sanitized = text
        findings: list[str] = []
        for rule in self.output_rules:
            sanitized, count = rule.pattern.subn(rule.replacement or "[REDACTED]", sanitized)
            if count:
                findings.append(rule.rule_id)
        return RedactionResult(sanitized, tuple(findings))
