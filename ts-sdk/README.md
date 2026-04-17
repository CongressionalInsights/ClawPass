# clawpass-sdk (TypeScript)

Install:

```bash
npm install clawpass-sdk
```

## Quickstart

```ts
import { ClawPassClient } from "clawpass-sdk";

const client = new ClawPassClient({ baseUrl: "http://localhost:8081" });

const request = await client.createApprovalRequest({
  request_id: "deploy-prod-2026-04-17",
  action_type: "outbound.send",
  action_hash: "sha256:...",
  risk_level: "high",
  callback_url: "https://producer.example/webhooks/clawpass",
});

const current = await client.getApprovalRequest(request.id);
console.log(current.status);
```

## Common methods

- `createApprovalRequest(payload)`
- `getApprovalRequest(requestId)`
- `listApprovalRequests(status?)`
- `cancelApprovalRequest(requestId, reason?)`
- `listWebhookEvents(filters?)`
- `getWebhookSummary()`
- `listWebhookEndpointSummaries(limit?)`
- `muteWebhookEndpoint(callbackUrl, options?)`
- `unmuteWebhookEndpoint(callbackUrl)`
- `pruneWebhookEvents()`
- `getWebhookPruneHistory(limit?)`
- `redeliverWebhookEvent(eventId)`
- `retryWebhookEventNow(eventId)`

## More guidance

For producer integration patterns and webhook handling guidance, use:
- [Integration Guide](../docs/integration-guide.md)
- [Webhook Operations](../docs/webhook-operations.md)
