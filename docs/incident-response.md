# Unsafe AI response playbook

## Detect

Trigger investigation when blocked-request volume rises sharply, a critical rule matches, output redaction occurs repeatedly, an unauthorized tool is requested, or evaluation pass rates regress.

## Contain

1. Disable the affected tool adapter or model route.
2. Revoke short-lived credentials associated with the workload identity.
3. Preserve hashed decision events, trace identifiers, deployment versions, and policy versions.
4. Route requests to a reduced-capability fallback that cannot invoke tools.

## Investigate

Correlate trace identifiers across the guardrail, model gateway, retrieval service, and tool adapter. Do not copy sensitive prompt content into tickets; use approved evidence storage and access controls.

## Recover

Add a minimized attack case to the evaluation dataset, update the policy or application boundary, rerun the full suite, and restore capabilities incrementally after approval.
