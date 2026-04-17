# Operator Runbook

This runbook is for humans operating a ClawPass instance.

## Startup

### Docker

```bash
docker compose up --build
```

### Local Python

```bash
source .venv/bin/activate
clawpass-server
```

## Primary health checks

Check these first:
- `GET /healthz`
- `GET /docs`
- `GET /v1/approval-requests`
- `GET /v1/webhook-summary`
- `GET /v1/webhook-endpoints/summary`

If the built-in UI is available, also open `/` and confirm the Webhook Ops panel renders current state.

## Routine checks

### Approval workflow checks

Review:
- pending request volume
- expired request count
- unexpected cancellations or denials
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
- health summary and alert list
- attention, failed, and stalled filters
- endpoint cards with mute state and failure counts
- endpoint-scoped event inspection
- mute/resume endpoint actions
- redelivery and retry-now actions
- prune history visibility

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
curl -X POST http://localhost:8081/v1/webhook-endpoints/mute \
  -H 'Content-Type: application/json' \
  -d '{"callback_url":"https://example.com/webhooks/clawpass","reason":"operator pause"}'
```

### Unmute an endpoint

Use this after the downstream destination is healthy again.

API:

```bash
curl -X POST http://localhost:8081/v1/webhook-endpoints/unmute \
  -H 'Content-Type: application/json' \
  -d '{"callback_url":"https://example.com/webhooks/clawpass"}'
```

### Redeliver a failed event

Use redelivery when a failed event should be replayed after the destination is healthy.

```bash
curl -X POST http://localhost:8081/v1/webhook-events/<event_id>/redeliver
```

### Force a queued stalled event to retry now

Use this only for queued events that are due and not actively leased.

```bash
curl -X POST http://localhost:8081/v1/webhook-events/<event_id>/retry-now
```

### Prune old settled history

Use prune to remove old delivered, skipped, or settled retry-chain history.

```bash
curl -X POST http://localhost:8081/v1/webhook-events/prune
```

Then confirm the recorded result:

```bash
curl http://localhost:8081/v1/webhook-prune-history
```

## Incident response

### Approval-path incident

1. Pause producer-side sensitive execution if necessary.
2. Identify affected request ids.
3. Verify the audit trail and request state.
4. Confirm whether the issue is verification, enrollment, expiration, or producer-side mismatch.

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
- approver enrollment state
- webhook delivery history
- audit events

## Upgrade procedure

1. Pull or build the new image.
2. Restart the service.
3. Validate:
   - `/healthz`
   - `/docs`
   - `/v1/approval-requests`
   - `/v1/webhook-summary`
4. Run one canary approval end to end.
5. If the release changed routes or schemas, confirm `docs/openapi.json` was updated in the release PR.

## Related docs

- [Webhook Operations](./webhook-operations.md)
- [Integration Guide](./integration-guide.md)
- [Recovery Model](./recovery-model.md)
- [Threat Model](./threat-model.md)
