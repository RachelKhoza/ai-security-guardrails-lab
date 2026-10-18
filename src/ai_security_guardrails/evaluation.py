from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .policy import PolicyEngine


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    expected_allowed: bool
    actual_allowed: bool
    violation_ids: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.expected_allowed == self.actual_allowed


def evaluate_dataset(engine: PolicyEngine, dataset_path: str | Path) -> list[CaseResult]:
    results: list[CaseResult] = []
    for line_number, line in enumerate(Path(dataset_path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        case = json.loads(line)
        decision = engine.evaluate(
            str(case["prompt"]),
            str(case.get("role", "viewer")),
            list(case.get("requested_tools", [])),
        )
        results.append(
            CaseResult(
                case_id=str(case.get("id", f"line-{line_number}")),
                expected_allowed=bool(case["expected_allowed"]),
                actual_allowed=decision.allowed,
                violation_ids=tuple(violation.rule_id for violation in decision.violations),
            )
        )
    return results


def render_markdown(results: list[CaseResult]) -> str:
    passed = sum(result.passed for result in results)
    lines = [
        "# Guardrail evaluation report",
        "",
        f"**Result:** {passed}/{len(results)} cases matched the expected policy decision.",
        "",
        "| Case | Expected | Actual | Status | Violations |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in results:
        violations = ", ".join(result.violation_ids) or "-"
        lines.append(
            f"| {result.case_id} | {_label(result.expected_allowed)} | "
            f"{_label(result.actual_allowed)} | {'PASS' if result.passed else 'FAIL'} | {violations} |"
        )
    lines.append("")
    return "\n".join(lines)


def _label(allowed: bool) -> str:
    return "allow" if allowed else "block"
