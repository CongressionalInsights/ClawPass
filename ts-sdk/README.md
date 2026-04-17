# clawpass-sdk (TypeScript)

```ts
import { ClawPassClient } from "clawpass-sdk";

const client = new ClawPassClient({ baseUrl: "http://localhost:8081" });
const request = await client.createApprovalRequest({
  request_id: "deploy-prod-2026-04-16",
  action_type: "outbound.send",
  action_hash: "sha256:...",
  risk_level: "high",
});

const pending = await client.listApprovalRequests("pending");
const cancelled = await client.cancelApprovalRequest(request.id, "operator cancelled");
const failed = await client.listWebhookEvents({ requestId: request.id, status: "failed", eventType: "approval.pending" });
const retried = await client.redeliverWebhookEvent(failed[0].id);
const pageTwo = await client.listWebhookEvents({ requestId: request.id, limit: 20, cursor: failed[0].id });
```
