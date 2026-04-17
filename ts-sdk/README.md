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
```
