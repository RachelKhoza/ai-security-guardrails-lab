from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import AuditSink
from .evaluation import evaluate_dataset, render_markdown
from .http_api import create_server
from .policy import PolicyEngine
from .service import GuardrailService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate AI requests against deterministic guardrails.")
    parser.add_argument("--policy", default="config/policy.toml", help="Path to the TOML policy file.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Evaluate one prompt and tool request.")
    check.add_argument("--prompt", required=True)
    check.add_argument("--role", default="viewer")
    check.add_argument("--tool", action="append", default=[])

    redact = subparsers.add_parser("redact", help="Redact sensitive values from model output.")
    redact.add_argument("--text", required=True)

    evaluate = subparsers.add_parser("evaluate", help="Run a JSONL adversarial evaluation dataset.")
    evaluate.add_argument("--dataset", default="evals/adversarial-cases.jsonl")
    evaluate.add_argument("--report", default="reports/evaluation-report.md")
    evaluate.add_argument("--fail-on-mismatch", action="store_true")

    serve = subparsers.add_parser("serve", help="Start the local JSON API.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--audit-log", default="audit/decisions.jsonl")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    engine = PolicyEngine.from_file(args.policy)

    if args.command == "check":
        decision = engine.evaluate(args.prompt, args.role, args.tool)
        print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
        return 0 if decision.allowed else 2

    if args.command == "redact":
        print(json.dumps(engine.redact(args.text).to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "evaluate":
        results = evaluate_dataset(engine, args.dataset)
        report = render_markdown(results)
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")
        mismatches = sum(not result.passed for result in results)
        print(f"Evaluated {len(results)} cases: {len(results) - mismatches} passed, {mismatches} mismatched.")
        return 1 if args.fail_on_mismatch and mismatches else 0

    service = GuardrailService(engine, AuditSink(args.audit_log))
    server = create_server((args.host, args.port), service)
    print(f"Listening on http://{args.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
