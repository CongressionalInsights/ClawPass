# Integration Guide

This guide is for systems that need to submit high-risk actions to ClawPass and consume the resulting decisions.

## Integration model

A producer system should treat ClawPass as the approval source of truth.

Producer authentication model:
- create the producer in `/app`
- issue a one-time-visible API key from the operator app
- send that key as `Authorization: Bearer cpk_<key_id>.<secret>`

The normal flow is:
1. Compute a stable action hash for the exact downstream payload.
2. Create an approval request in ClawPass under producer API-key auth.
3. Hold the risky side effect while the request is `PENDING`.
4. Wait for a final state by polling or by consuming webhook events.
5. Re-fetch the request from ClawPass under producer auth.
6. Before executing the downstream side effect, verify the returned `status`, `request_id`, `producer_id`, `action_hash`, and any local `action_ref` assumptions still match the intended action.

Do not treat a bare callback as enough proof to execute arbitrary work without checking the original action binding.

## Creating an approval request

Authentication:

```http
Authorization: Bearer cpk_<key_id>.<secret>
```

Required request fields:
- `action_type`
- `action_hash`

Common optional fields:
- `request_id`: caller-supplied idempotency key
- `action_ref`: producer-side external reference
- `requester_id`: producer/user identity
- `risk_level`
- `metadata`
- `expires_at`
- `callback_url`

### Why `request_id` matters

If the producer may retry the request-creation call, send a caller-controlled `request_id`. ClawPass treats duplicates as a conflict instead of creating silent duplicates.

## What the response gives back

Approval-request responses now include:
- `producer_id`: the authenticated ClawPass producer identity derived from the API key
- `approval_url`: the human-facing approval link for the request

The producer should treat `producer_id` as audited server state, not as caller-supplied metadata.

The `approval_url` is the human-facing link that ClawPass returns to the producer. Share that URL with the intended approver, or embed it in operator tooling, instead of constructing approval URLs yourself.

## Final approval states

A producer should treat these states as terminal:
- `APPROVED`
- `DENIED`
- `EXPIRED`
- `CANCELLED`

`PENDING` is the only non-terminal state.

## Polling pattern

If you do not want to rely only on callbacks, poll:
- `GET /v1/approval-requests/{request_id}`

This route also requires the producer bearer token.

This is also the safest fallback when your callback consumer is degraded.

## Webhook pattern

If you provide a `callback_url`, ClawPass records and delivers webhook events for lifecycle changes.

Recommended producer posture:
- make your webhook consumer idempotent
- record processed event ids
- verify the payload still matches the intended action before executing side effects
- continue to support polling as a reconciliation path

See [Webhook Operations](./webhook-operations.md) for delivery semantics and headers.

## Python SDK quickstart

```python
from clawpass_sdk_py import ClawPassClient

client = ClawPassClient(
    "http://localhost:8081",
    api_key="cpk_<key_id>.<secret>",
)
request = client.create_approval_request(
    request_id="deploy-prod-2026-04-17",
    action_type="outbound.send",
    action_hash="sha256:...",
    risk_level="high",
    requester_id="producer-a",
    callback_url="https://producer.example/webhooks/clawpass",
)

current = client.get_approval_request(request["id"])
if current["status"] == "APPROVED":
    assert current["producer_id"] == request["producer_id"]
    assert current["action_hash"] == request["action_hash"]
```

Useful Python SDK methods:
- `create_gated_action(...)`
- `get_approval_request(...)`
- `list_approval_requests(...)`
- `cancel_approval_request(...)`
- `wait_for_final_decision(...)`
- `verify_approved_request(...)`

The Python SDK fits the producer loop best. Admin-only routes can still be called if you supply the browser session cookie and CSRF header explicitly through `headers=...`, but `/app` remains the primary operator experience.

## TypeScript SDK quickstart

```ts
import { ClawPassClient } from "clawpass-sdk";

const client = new ClawPassClient({
  baseUrl: "http://localhost:8081",
  apiKey: "cpk_<key_id>.<secret>",
});
const request = await client.createApprovalRequest({
  request_id: "deploy-prod-2026-04-17",
  action_type: "outbound.send",
  action_hash: "sha256:...",
  risk_level: "high",
  callback_url: "https://producer.example/webhooks/clawpass",
});

const current = await client.getApprovalRequest(request.id);
if (current.status === "APPROVED") {
  if (current.producer_id !== request.producer_id) throw new Error("Producer mismatch");
  if (current.action_hash !== request.action_hash) throw new Error("Hash mismatch");
}
```

Useful TypeScript SDK methods mirror the HTTP API closely.
For the producer hold/resume loop, prefer:
- `createGatedAction(...)`
- `waitForFinalDecision(...)`
- `verifyApprovedRequest(...)`

## HTTP routes most producer systems use

Approval flow:
- `POST /v1/approval-requests`
- `GET /v1/approval-requests/{request_id}`
- `GET /v1/approval-requests?status=...`
- `POST /v1/approval-requests/{request_id}/cancel`

Operator routes such as webhook visibility, producer issuance, and approval decisions are admin-session routes intended for `/app`.

## Callback consumer checklist

Before executing the downstream action on an approved event, the consumer should check:
- the event is for the expected `request_id`
- the payload `status` is `APPROVED`
- the payload `producer_id` matches the producer that created the request
- the payload `action_hash` still matches the intended action payload
- the local side effect has not already been executed for that request id

## Recommended producer safeguards

- Use caller-supplied `request_id` values for idempotency.
- Keep the producer-side action payload immutable once submitted for approval.
- Store the original action hash locally so callback handlers can re-check it.
- Treat polling and webhook delivery as complementary, not mutually exclusive.
- Do not expose a callback endpoint that blindly executes on receipt of a payload.

## Related docs

- [Webhook Operations](./webhook-operations.md)
- [Architecture Overview](./architecture.md)
- [OpenAPI Export](./openapi.md)
