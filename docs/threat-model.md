# Threat model

## Assets

- Trusted system and developer instructions.
- Data returned by model providers, retrieval systems, and tools.
- Tool credentials and the authority attached to the calling identity.
- Audit evidence needed to investigate unsafe model behaviour.

## Trust boundaries

```text
untrusted user input
  -> guardrail decision point
  -> model or retrieval service
  -> output redaction
  -> caller

identity and requested tools
  -> role/tool authorization
  -> approved tool adapter
```

## Controls

| Risk area | Control in this repository |
| --- | --- |
| Prompt injection | Unicode normalization and configurable detection rules block common instruction-override and prompt-extraction requests. |
| Sensitive information disclosure | Output rules redact access-key shapes, bearer tokens, and email addresses before delivery. |
| Excessive agency | Each role has an explicit tool allowlist; high-risk tools remain blocked for every role. |
| Unbounded input | Prompt length, request body size, and requested tool count have explicit limits. |
| Unsafe observability | Audit events store prompt and session hashes, not raw prompts or model output. |

## Residual risks

Pattern matching is a deterministic first layer, not a complete prompt-injection defence. Production systems should combine these controls with model-provider safety features, retrieval isolation, short-lived identity, human approval for high-impact actions, rate limiting, continuous adversarial evaluation, and incident monitoring.
