# Operator Runbook

This runbook is for humans operating a ClawPass instance.

## Startup

### Docker

```bash
export CLAWPASS_BASE_URL=https://clawpass.example.com
export CLAWPASS_EXPECTED_ORIGIN=https://clawpass.example.com
export CLAWPASS_RP_ID=clawpass.example.com
export CLAWPASS_BOOTSTRAP_TOKEN=replace-with-a-long-random-bootstrap-token
export CLAWPASS_SESSION_SECRET=replace-with-a-long-random-session-secret
docker compose up --build
```

### Local Python

```bash
source .venv/bin/activate
export CLAWPASS_BASE_URL=http://localhost:8081
export CLAWPASS_BOOTSTRAP_TOKEN=dev-bootstrap-token
export CLAWPASS_SESSION_SECRET=dev-session-secret
clawpass-server
```

## First-run bootstrap

On a new instance:
1. Open `/setup`.
2. Enter `CLAWPASS_BOOTSTRAP_TOKEN`.
3. Enroll the first admin passkey.
4. Confirm you land in `/app`.
5. Create the first producer and issue its API key.
6. Create approver invites for any additional human approvers.

On later visits:
- `/login` performs passkey-based human login.
- `/app` is the authenticated operator surface.
- non-admin approvers should usually enter through an invite URL or an `approval_url`

## Primary health checks

Check these first:
- `GET /healthz`
- `GET /docs`
- `GET /v1/setup/status`

If the built-in UI is available, also open `/` and confirm it routes to `/setup`, `/login`, or `/app` as expected.

## Routine checks

### Approval workflow checks

Review:
- pending request volume
- expired request count
- unexpected cancellations or denials
- producer identities creating requests
- approver summary counts for the passkey floor on high-risk approvers

### Webhook checks

Review:
- stalled backlog
- scheduled retries
- dead-lettered events
- failure-rate alerts
- endpoint summaries with concentrated failures
- prune history if regular retention jobs are expected

## Using the built-in operator dashboard

The current dashboard supports:
- session summary with admin status
- passkey and Ledger enrollment actions
- approver list and invite creation
- producer creation and API-key issuance
- health summary and alert list
- endpoint cards with mute state and failure counts
- mute and resume endpoint actions
- prune action and backlog visibility

Use the dashboard for triage, but use the API when you need scripted or repeatable operator workflows.

## Common operator actions

### Inspect a noisy destination

1. Open endpoint summaries.
2. Select the affected `callback_url`.
3. Inspect failed and stalled events for that endpoint.
4. Confirm whether the problem is destination-specific or system-wide.

### Mute an endpoint

Use this when a destination is repeatedly failing and continuing to deliver would create noise or load.

API:

```bash
export CLAWPASS_SESSION=...
export CLAWPASS_CSRF=...

curl -X POST http://localhost:8081/v1/webhook-endpoints/mute \
  -H "Cookie: clawpass_session=${CLAWPASS_SESSION}" \
  -H "X-ClawPass-CSRF: ${CLAWPASS_CSRF}" \
  -H 'Content-Type: application/json' \
  -d '{"callback_url":"https://example.com/webhooks/clawpass","reason":"operator pause"}'
```

### Unmute an endpoint

Use this after the downstream destination is healthy again.

API:

```bash
curl -X POST http://localhost:8081/v1/webhook-endpoints/unmute \
  -H "Cookie: clawpass_session=${CLAWPASS_SESSION}" \
  -H "X-ClawPass-CSRF: ${CLAWPASS_CSRF}" \
  -H 'Content-Type: application/json' \
  -d '{"callback_url":"https://example.com/webhooks/clawpass"}'
```

### Redeliver a failed event

Use redelivery when a failed event should be replayed after the destination is healthy.

```bash
curl -X POST http://localhost:8081/v1/webhook-events/<event_id>/redeliver \
  -H "Cookie: clawpass_session=${CLAWPASS_SESSION}" \
  -H "X-ClawPass-CSRF: ${CLAWPASS_CSRF}"
```

### Force a queued stalled event to retry now

Use this only for queued events that are due and not actively leased.

```bash
curl -X POST http://localhost:8081/v1/webhook-events/<event_id>/retry-now \
  -H "Cookie: clawpass_session=${CLAWPASS_SESSION}" \
  -H "X-ClawPass-CSRF: ${CLAWPASS_CSRF}"
```

### Prune old settled history

Use prune to remove old delivered, skipped, or settled retry-chain history.

```bash
curl -X POST http://localhost:8081/v1/webhook-events/prune \
  -H "Cookie: clawpass_session=${CLAWPASS_SESSION}" \
  -H "X-ClawPass-CSRF: ${CLAWPASS_CSRF}"
```

Then confirm the recorded result:

```bash
curl \
  -H "Cookie: clawpass_session=${CLAWPASS_SESSION}" \
  http://localhost:8081/v1/webhook-prune-history
```

## Incident response

### Approval-path incident

1. Pause producer-side sensitive execution if necessary.
2. Identify affected request ids.
3. Verify the audit trail and request state.
4. Confirm whether the issue is verification, enrollment, expiration, auth, or producer-side mismatch.

### Webhook incident

1. Check `GET /v1/webhook-summary`.
2. Identify whether the issue is:
   - system-wide backlog,
   - a single failing destination,
   - dead-letter exhaustion,
   - repeated auto-mute on one endpoint.
3. Inspect the affected endpoint summary and event rows.
4. Repair the downstream consumer.
5. Unmute or redeliver as needed.
6. Confirm delivery stabilizes afterward.

## Backup and recovery

Persist the SQLite database path on a regular schedule.

For the compose setup, that means preserving the mounted data volume backing `/data/clawpass.db`.

Backups matter for:
- approval request history
- producer registry and API-key metadata
- approver enrollment state
- admin sessions and bootstrap state
- webhook delivery history
- audit events

## Upgrade procedure

1. Pull or build the new image.
2. Restart the service.
3. Validate:
   - `/healthz`
   - `/docs`
   - `/v1/setup/status`
   - `/login`
4. Run one canary approval end to end.
5. If the release changed routes or schemas, confirm `docs/openapi.json` was updated in the release PR.

## Related docs

- [Webhook Operations](./webhook-operations.md)
- [Integration Guide](./integration-guide.md)
- [Recovery Model](./recovery-model.md)
- [Threat Model](./threat-model.md)
