# ledgerclaw-sdk (TypeScript)

```ts
import { LedgerClawClient } from "ledgerclaw-sdk";

const client = new LedgerClawClient({ baseUrl: "http://localhost:8081" });
const request = await client.createApprovalRequest({
  action_type: "outbound.send",
  action_hash: "sha256:...",
  risk_level: "high",
});
```
