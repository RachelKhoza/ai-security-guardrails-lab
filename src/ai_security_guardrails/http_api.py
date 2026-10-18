from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .service import GuardrailService

MAX_BODY_BYTES = 65_536


def create_server(address: tuple[str, int], service: GuardrailService) -> ThreadingHTTPServer:
    class GuardrailHandler(BaseHTTPRequestHandler):
        server_version = "AISecurityGuardrails/0.1"

        def _send(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict[str, object]:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_BODY_BYTES:
                raise ValueError(f"request body must be between 1 and {MAX_BODY_BYTES} bytes")
            payload = json.loads(self.rfile.read(content_length))
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(HTTPStatus.OK, {"status": "ok"})
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            try:
                payload = self._read_json()
                if self.path == "/v1/evaluate":
                    response = service.evaluate(payload, self.headers.get("X-Trace-ID"))
                    self._send(HTTPStatus.OK, response)
                elif self.path == "/v1/redact":
                    self._send(HTTPStatus.OK, service.redact(payload).to_dict())
                else:
                    self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            except (json.JSONDecodeError, ValueError) as error:
                self._send(HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "detail": str(error)})

        def log_message(self, format_string: str, *args: object) -> None:
            return

    return ThreadingHTTPServer(address, GuardrailHandler)
