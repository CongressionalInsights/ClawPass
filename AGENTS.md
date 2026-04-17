# AGENTS.md

This file is for coding agents working inside the ClawPass repo.

For shared contributor workflow, setup, validation commands, and the repo map, use [CONTRIBUTING.md](./CONTRIBUTING.md) as the canonical source.

## Agent goals

Keep changes small, contract-first, and fully synchronized across runtime behavior, SDKs, tests, and docs.

## Agent source of truth

When documenting or changing behavior, prefer these files in order:
1. `src/clawpass_server/core/service.py`
2. `src/clawpass_server/core/webhooks.py`
3. `src/clawpass_server/api/routes.py`
4. tests under `tests/`
5. SDK surfaces
6. docs

Do not document or implement features that are not present in those surfaces.

## Current product constraints

- Approval requests are single-request objects with durable statuses.
- Supported decision methods are `webauthn`, `ledger_webauthn`, and `ethereum_signer`.
- High-risk approvals require at least one non-ledger passkey.
- Webhook operations are first-class and include retry, dead-lettering, endpoint mute/unmute, prune history, and dashboard actions.
- External transition compatibility still exists for some legacy `LEDGERCLAW_*` env vars and dual webhook headers.

## Required sync points

If you change routes or schemas, update all of:
- `docs/openapi.json`
- Python SDK if relevant
- TypeScript SDK if relevant
- tests
- docs that describe the changed behavior

If you change webhook behavior, also update:
- `docs/operator-runbook.md`
- `docs/webhook-operations.md`
- dashboard behavior in `src/clawpass_server/web/`

## Validation rule

Use the repo-local `.venv`, and treat [CONTRIBUTING.md](./CONTRIBUTING.md) as the canonical source for the full validation command set.

For runtime changes, the minimum meaningful validation still includes:
- `pytest -q`
- `python3 scripts/check_sdk_roundtrip.py`
- `npx -y -p tsx tsx scripts/check_ts_sdk_roundtrip.ts`
- `npx -y -p typescript tsc --noEmit ts-sdk/src/index.ts`
- `node --check src/clawpass_server/web/app.js`

## Autoresearch

Use the repo-local harness for bounded improvement loops. Keep changed files inside the allowed surface declared in `autoresearch/benchmark-pack.*.json` and use [CONTRIBUTING.md](./CONTRIBUTING.md) for the canonical fast/full pack commands.

## Documentation rules

Prefer adding precise repo-local docs over expanding README into a wall of text.

The current doc map is:
- `README.md`: entrypoint and doc map
- `docs/architecture.md`: system concepts and boundaries
- `docs/integration-guide.md`: producer integration path
- `docs/webhook-operations.md`: webhook semantics and operator actions
- `docs/operator-runbook.md`: routine checks and incident handling
- `docs/passkey-guide.md`, `docs/ledger-setup.md`, `docs/recovery-model.md`, `docs/threat-model.md`: focused user/operator references

## Avoid

- broad rewrites that mix unrelated seams
- documentation that invents auth, tenancy, or deployment models not in the code
- claims of green validation when checks were not actually run
