# Operator Runbook

## Startup

```bash
docker compose up --build
```

## Health checks

- `GET /healthz`
- `GET /docs`
- `GET /v1/approval-requests`

## Routine checks

- Pending requests volume and stale pending items
- Failed webhook deliveries via `GET /v1/webhook-events`
- Approver summary counts for required passkey floor

## Incident response

1. Pause producer-side sensitive execution.
2. Identify affected request ids and verify audit trail.
3. Check webhook failures and replay producer reconciliation.
4. Revalidate approver credential/signer enrollment.

## Backup

Persist `/data/ledgerclaw.db` on a regular schedule.

## Upgrade

1. Pull new image.
2. Restart service.
3. Validate `/healthz` and core API routes.
4. Run one canary approval end-to-end.
