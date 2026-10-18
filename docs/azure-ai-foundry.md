# Azure AI Foundry integration pattern

The guardrail service is deliberately model-independent. Place it in front of an Azure AI Foundry model endpoint or agent and keep model credentials out of application configuration.

## Recommended request path

1. Authenticate the calling workload with Microsoft Entra ID.
2. Pass the caller's application role and proposed tool calls to `/v1/evaluate`.
3. Stop the request when the decision is `block`.
4. Use managed identity to call the model deployment when the decision is `allow`.
5. Send model output through `/v1/redact` before returning it to the caller.
6. Export decision metadata and model telemetry using a shared trace identifier.

## Identity controls

- Use a dedicated managed identity for the AI workload.
- Assign only the data-plane role required to invoke the selected model deployment.
- Give retrieval and action tools separate identities and permissions.
- Require approval outside the model for destructive or high-impact actions.
- Keep secrets in Azure Key Vault and do not expose secret-reading tools to the model.

## Production additions

Add private endpoints, network isolation, Azure Monitor alerts, content filtering, rate limits, encrypted audit storage, retention controls, and an evaluation pipeline that includes domain-specific attacks.
