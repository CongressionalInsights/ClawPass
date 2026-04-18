# clawpass-sdk (TypeScript)

Install:

```bash
npm install clawpass-sdk
```

## Quickstart

```ts
import { ClawPassClient } from "clawpass-sdk";

const client = new ClawPassClient({
  baseUrl: "http://localhost:8081",
  apiKey: "cpk_<key_id>.<secret>",
});

const request = await client.createGatedAction({
  request_id: "deploy-prod-2026-04-17",
  action_type: "outbound.send",
  action_hash: "sha256:...",
  risk_level: "high",
  callback_url: "https://producer.example/webhooks/clawpass",
});

const terminal = await client.waitForFinalDecision(request.id);
if (terminal.status === "APPROVED") {
  client.verifyApprovedRequest(terminal, {
    requestId: request.id,
    actionHash: request.action_hash,
    producerId: request.producer_id ?? undefined,
  });
}
```

## Producer methods

- `createGatedAction(payload)`
- `createApprovalRequest(payload)`
- `getApprovalRequest(requestId)`
- `listApprovalRequests(status?)`
- `cancelApprovalRequest(requestId, reason?)`
- `waitForFinalDecision(requestId, options?)`
- `verifyApprovedRequest(request, expected?)`

## Advanced operator methods

The client also exposes webhook and operator helpers, but those routes require the authenticated operator session rather than a producer API key. To use them, pass the browser session cookie and CSRF header through `headers`.

## More guidance

For producer integration patterns and webhook handling guidance, use:
- [Integration Guide](../docs/integration-guide.md)
- [Webhook Operations](../docs/webhook-operations.md)
