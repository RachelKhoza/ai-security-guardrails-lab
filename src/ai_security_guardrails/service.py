from __future__ import annotations

from .audit import AuditSink
from .models import RedactionResult
from .policy import PolicyEngine


class GuardrailService:
    def __init__(self, engine: PolicyEngine, audit_sink: AuditSink | None = None) -> None:
        self.engine = engine
        self.audit_sink = audit_sink or AuditSink()

    def evaluate(self, payload: dict[str, object], trace_id: str | None = None) -> dict[str, object]:
        prompt = payload.get("prompt")
        role = payload.get("role", "viewer")
        requested_tools = payload.get("requested_tools", [])
        session_id = payload.get("session_id", "anonymous")

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt must be a non-empty string")
        if not isinstance(role, str):
            raise ValueError("role must be a string")
        if not isinstance(session_id, str):
            raise ValueError("session_id must be a string")
        if not isinstance(requested_tools, list) or not all(
            isinstance(tool, str) for tool in requested_tools
        ):
            raise ValueError("requested_tools must be an array of strings")

        decision = self.engine.evaluate(prompt, role, requested_tools)
        event = self.audit_sink.record(
            prompt=prompt,
            session_id=session_id,
            trace_id=trace_id,
            decision=decision,
        )
        response = decision.to_dict()
        response["event_id"] = event["event_id"]
        response["trace_id"] = event["trace_id"]
        return response

    def redact(self, payload: dict[str, object]) -> RedactionResult:
        text = payload.get("text")
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return self.engine.redact(text)
