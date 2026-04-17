# Architecture Overview

This document explains the current ClawPass system as it exists in the repo today.

## What ClawPass does

ClawPass is an approval service for high-risk actions. A producer system submits an approval request, one or more approvers review and complete the decision using a supported cryptographic method, and ClawPass exposes the resulting lifecycle through the API, webhook delivery, SDKs, and built-in UI.

The implementation is intentionally compact. There is one FastAPI application, one SQLite persistence layer, one core service layer, and thin SDKs that mirror the HTTP surface.

## Main system boundaries

### API layer

`src/clawpass_server/api/routes.py` defines the public HTTP contract. The route layer is intentionally thin and delegates almost all behavior to `ClawPassService`.

### Core service layer

`src/clawpass_server/core/service.py` is the main product contract. It owns:
- approval request creation and state transitions,
- approver summaries,
- decision challenge flows,
- webhook event listing and operator actions,
- webhook endpoint summaries and prune history.

If a behavior change matters to external callers, it almost always passes through this file.

### Verification adapters

`src/clawpass_server/adapters/` contains method-specific verification logic:
- WebAuthn / passkeys
- Ethereum typed-signature verification

These adapters verify method-specific proofs, but they do not own approval lifecycle policy.

### Persistence

`src/clawpass_server/core/database.py` manages the SQLite schema and startup migrations.

Important tables:
- `approval_requests`: durable approval intent and final status
- `decision_challenges`: short-lived approval challenges
- `approvers`: approver identity records
- `webauthn_credentials`: passkeys and Ledger security-key credentials
- `ethereum_signers`: Ledger-backed or other Ethereum signer identities
- `webhook_events`: delivery log, retry chain, lease state, dead-letter state
- `webhook_endpoint_controls`: endpoint mute state and consecutive failure counts
- `audit_events`: append-only audit log for operator and lifecycle events

### Webhook dispatcher

`src/clawpass_server/core/webhooks.py` owns delivery behavior:
- queueing
- lease claims
- immediate retry for transient failures
- scheduled retry with jitter
- dead-letter marking after budget exhaustion
- endpoint auto-mute / circuit-breaker behavior
- queued-event recovery on startup and in the background loop

### Browser UI

`src/clawpass_server/web/` contains the built-in onboarding and operator UI. It is not a separate SPA deployment. It is served directly by the FastAPI app.

The UI currently covers two major workflows:
- approver onboarding and method enrollment
- webhook operator triage and actions

### SDKs

ClawPass ships two thin SDKs:
- Python: `src/clawpass_sdk_py/`
- TypeScript: `ts-sdk/`

They intentionally stay close to the HTTP contract rather than adding a large client-side abstraction layer.

## Approval lifecycle

An approval request starts as `PENDING` and can move to one of:
- `APPROVED`
- `DENIED`
- `EXPIRED`
- `CANCELLED`

Important constraints:
- requests are hash-bound to the intended action
- decision proofs are bound to request id, action hash, nonce, and expiry
- high-risk approvals require at least one non-ledger passkey for the approver

## Supported approval methods

### `webauthn`

A standard passkey-backed approval.

### `ledger_webauthn`

A Ledger used as a FIDO/WebAuthn security key.

### `ethereum_signer`

A Ledger-backed Ethereum account signs an EIP-712 typed challenge, and ClawPass verifies signer ownership.

## Webhook subsystem model

Every state transition can create a webhook event if the originating approval request included a `callback_url`.

Webhook delivery is not fire-and-forget. Each event is recorded and moves through delivery states such as:
- `queued`
- `delivered`
- `failed`
- `skipped`

The dispatcher also tracks:
- lease ownership for in-flight work
- retry parent chains
- retry attempt counters
- dead-letter timestamps and reasons
- endpoint mute state and consecutive failures

This is why webhook operations are a first-class operator surface in the repo.

## Operator model

ClawPass now exposes operator-facing webhook controls through both the API and the built-in UI.

Operators can:
- inspect backlog and failure summaries
- inspect endpoint health
- filter events by request, status, event type, or callback URL
- mute and unmute a destination
- redeliver a failed event
- force a queued event to retry immediately
- prune old settled history
- review prune history

## Configuration model

The runtime is configured through environment variables loaded in `src/clawpass_server/core/config.py`.

The main groups are:
- server bind settings: host, port, database path
- WebAuthn relying party settings: RP id, RP name, expected origins
- TTL settings: challenge and approval defaults
- webhook delivery settings: timeout, lease seconds, retry poll interval
- retry policy: base delay, max delay, jitter, retry limit
- operator thresholds: backlog alert threshold, failure-rate alert threshold
- retention settings: event retention days, retry-history retention days
- circuit-breaker settings: endpoint auto-mute threshold and mute duration
- optional webhook HMAC secret

Legacy `LEDGERCLAW_*` env vars still fall back to the new `CLAWPASS_*` names where explicitly supported.

## Deployment model

ClawPass is currently a single-process service with local SQLite persistence by default.

The repo supports:
- local `.venv` development
- Docker image build via `Dockerfile`
- local compose startup via `docker-compose.yml`

The current webhook queue and lease design is safe for multiple app instances sharing the same SQLite database at the claim level, but the deployment model is still intentionally simple.

## Documentation map

Use the focused docs for the next layer of detail:
- [Integration Guide](./integration-guide.md): producer-facing HTTP and SDK usage
- [Webhook Operations](./webhook-operations.md): webhook semantics and operator actions
- [Operator Runbook](./operator-runbook.md): routine checks and incident response
- [Passkey Guide](./passkey-guide.md): approver onboarding
- [Ledger Setup Guide](./ledger-setup.md): Ledger-specific enrollment paths
