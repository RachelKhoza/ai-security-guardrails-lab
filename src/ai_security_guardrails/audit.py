from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .models import Decision


class AuditSink:
    """Writes decision metadata without storing raw prompts or model output."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def record(
        self,
        *,
        prompt: str,
        session_id: str,
        trace_id: str | None,
        decision: Decision,
    ) -> dict[str, object]:
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_id": str(uuid.uuid4()),
            "trace_id": trace_id or str(uuid.uuid4()),
            "session_hash": self._digest(session_id)[:20],
            "prompt_hash": self._digest(prompt),
            "role": decision.role,
            "requested_tools": list(decision.requested_tools),
            "allowed": decision.allowed,
            "action": decision.action,
            "violation_ids": [violation.rule_id for violation in decision.violations],
        }
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock, self.path.open("a", encoding="utf-8") as audit_file:
                audit_file.write(json.dumps(event, sort_keys=True) + "\n")
        return event
