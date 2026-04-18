# Webhook Operations

This guide covers ClawPass webhook behavior as implemented today.

## What a webhook event is

A webhook event is a recorded delivery attempt for an approval lifecycle event associated with a request that was created with a `callback_url`.

The event log is durable. ClawPass does not rely on transient in-memory callbacks.

## Event types

Current approval lifecycle events include:
- `approval.pending`
- `approval.approved`
- `approval.denied`
- `approval.expired`
- `approval.cancelled`

## Delivery states

Webhook event rows can appear in states such as:
- `queued`
- `delivered`
- `failed`
- `skipped`

Additional delivery metadata includes:
- `attempt_count`
- `available_at`
- `lease_expires_at`
- `retry_parent_id`
- `retry_attempt`
- `dead_lettered_at`
- `dead_letter_reason`

## Delivery model

ClawPass webhook delivery behavior includes:
- enqueue on event creation when a callback URL exists
- lease-backed claim before delivery
- immediate retry for transient failures during a delivery attempt
- scheduled retry with jitter when retryable failures remain unresolved
- dead-letter marking when the automatic retry budget is exhausted
- recovery of queued work on startup and in the background poll loop

## Circuit breaker and endpoint mute behavior

ClawPass now tracks endpoint-level controls by `callback_url`.

An endpoint can become muted in two ways:
- automatically after repeated consecutive delivery failures, based on configured threshold and mute duration
- manually through operator actions

While an endpoint is muted:
- queued events remain recorded
- delivery is deferred by moving `available_at` forward
- operator summaries still show the backlog and mute state

When the endpoint is unmuted:
- releasable queued work is made available again
- operators can inspect, retry, or redeliver as needed

## Headers

ClawPass sends event metadata headers with each delivery.

Current headers include:
- `X-ClawPass-Webhook-Id`
- `X-ClawPass-Event`

Transition compatibility headers may also be present:
- `X-LedgerClaw-Webhook-Id`
- `X-LedgerClaw-Event`

If a webhook secret is configured, ClawPass also sends HMAC signature headers:
- `X-ClawPass-Signature`
- `X-LedgerClaw-Signature`

## Signature verification

If you enable `CLAWPASS_WEBHOOK_SECRET`, verify the HMAC before trusting the body.

Even after signature verification, callback consumers should still:
- check `request_id`
- check final status
- re-check `action_hash` before executing the downstream side effect

## Operator API surfaces

These routes are operator routes, not producer routes.

Authentication model:
- `GET` routes require an authenticated admin session cookie
- `POST` routes require the admin session cookie plus the matching `X-ClawPass-CSRF` header
- the canonical session cookie is `clawpass_session`
- the built-in `/app` UI is the primary operator surface for these actions

### Event listing

`GET /v1/webhook-events`

Supported filters include:
- `request_id`
- `status`
- `event_type`
- `callback_url`
- `limit`
- `cursor`

### Aggregate summary

`GET /v1/webhook-summary`

Useful for:
- backlog
- leased backlog
- stalled backlog
- scheduled retries
- dead-letter counts
- redelivery outcome counts
- overall alerts

### Endpoint summaries

`GET /v1/webhook-endpoints/summary`

Useful for:
- destination-specific failure rate
- destination mute state
- consecutive failure counts
- queued and stalled counts
- latest error and next attempt

### Manual controls

- `POST /v1/webhook-endpoints/mute`
- `POST /v1/webhook-endpoints/unmute`
- `POST /v1/webhook-events/{event_id}/redeliver`
- `POST /v1/webhook-events/{event_id}/retry-now`
- `POST /v1/webhook-events/prune`
- `GET /v1/webhook-prune-history`

## Built-in operator dashboard

The built-in UI now supports:
- top-level webhook health summary
- endpoint health cards
- endpoint mute and resume actions
- manual prune action
- prune-history review

## Recommended operator workflow

### When failures appear

1. Check `GET /v1/webhook-summary` or the dashboard health panel.
2. Inspect endpoint summaries to find concentrated failures by `callback_url`.
3. Filter event rows to the affected destination.
4. Decide whether to:
   - fix the destination and wait,
   - temporarily mute the endpoint,
   - redeliver a failed event,
   - retry a stalled queued event now.

### When dead-letter events appear

1. Inspect the root failure cause and the retry chain.
2. Confirm the downstream destination is healthy again.
3. Use redelivery for failed events that should be replayed.
4. Keep polling or inspecting until delivery stabilizes.

### When history grows large

1. Review the current endpoint and event state first.
2. Use prune only to remove old settled history.
3. Review prune history afterward to confirm what was removed.

## Retention behavior

ClawPass prunes old settled delivery history based on configured retention windows.

Current retention areas are:
- delivered or skipped root events
- settled retry-history chains

Queued work is intentionally preserved and is not eligible for prune while still active.

## Environment variables that affect webhook behavior

Important settings include:
- `CLAWPASS_WEBHOOK_TIMEOUT_SECONDS`
- `CLAWPASS_WEBHOOK_DELIVERY_LEASE_SECONDS`
- `CLAWPASS_WEBHOOK_RETRY_POLL_SECONDS`
- `CLAWPASS_WEBHOOK_AUTO_RETRY_LIMIT`
- `CLAWPASS_WEBHOOK_AUTO_RETRY_BASE_DELAY_SECONDS`
- `CLAWPASS_WEBHOOK_AUTO_RETRY_MAX_DELAY_SECONDS`
- `CLAWPASS_WEBHOOK_AUTO_RETRY_JITTER_SECONDS`
- `CLAWPASS_WEBHOOK_EVENT_RETENTION_DAYS`
- `CLAWPASS_WEBHOOK_RETRY_HISTORY_RETENTION_DAYS`
- `CLAWPASS_WEBHOOK_ENDPOINT_AUTO_MUTE_THRESHOLD`
- `CLAWPASS_WEBHOOK_ENDPOINT_AUTO_MUTE_SECONDS`
- `CLAWPASS_WEBHOOK_SECRET`

## Related docs

- [Operator Runbook](./operator-runbook.md)
- [Integration Guide](./integration-guide.md)
- [Architecture Overview](./architecture.md)
