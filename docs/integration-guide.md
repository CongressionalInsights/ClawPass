# Integration Guide

This guide is for systems that need to submit high-risk actions to ClawPass and consume the resulting decisions.

## Integration model

A producer system should treat ClawPass as the approval source of truth.

The normal flow is:
1. Compute a stable action hash for the exact downstream payload.
2. Create an approval request in ClawPass.
3. Wait for a final state by polling or by consuming webhook events.
4. Before executing the downstream side effect, verify the returned `action_hash` and any local `action_ref` assumptions still match the intended action.

Do not treat a bare callback as enough proof to execute arbitrary work without checking the original action binding.

## Creating an approval request

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

client = ClawPassClient("http://localhost:8081")
request = client.create_approval_request(
    request_id="deploy-prod-2026-04-17",
    action_type="outbound.send",
    action_hash="sha256:...",
    risk_level="high",
    requester_id="producer-a",
    callback_url="https://producer.example/webhooks/clawpass",
)

current = client.get_approval_request(request["id"])
summary = client.get_webhook_summary()
```

Useful Python SDK methods:
- `create_approval_request(...)`
- `get_approval_request(...)`
- `list_approval_requests(...)`
- `cancel_approval_request(...)`
- `list_webhook_events(...)`
- `get_webhook_summary()`
- `list_webhook_endpoint_summaries(...)`
- `mute_webhook_endpoint(...)`
- `unmute_webhook_endpoint(...)`
- `prune_webhook_events()`
- `get_webhook_prune_history(...)`
- `redeliver_webhook_event(...)`
- `retry_webhook_event_now(...)`

## TypeScript SDK quickstart

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
const events = await client.listWebhookEvents({ requestId: request.id, limit: 20 });
```

Useful TypeScript SDK methods mirror the HTTP API closely.

## HTTP routes most producer systems use

Approval flow:
- `POST /v1/approval-requests`
- `GET /v1/approval-requests/{request_id}`
- `GET /v1/approval-requests?status=...`
- `POST /v1/approval-requests/{request_id}/cancel`

Operator and webhook visibility:
- `GET /v1/webhook-events`
- `GET /v1/webhook-summary`
- `GET /v1/webhook-endpoints/summary`

## Callback consumer checklist

Before executing the downstream action on an approved event, the consumer should check:
- the event is for the expected `request_id`
- the payload `status` is `APPROVED`
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
