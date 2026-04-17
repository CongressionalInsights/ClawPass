# AGENTS.md

This file is for coding agents working inside the ClawPass repo.

## Goals

Keep changes small, contract-first, and fully synchronized across runtime behavior, SDKs, tests, and docs.

## Setup

Use the repo-local virtualenv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Do not assume system Python has the required dependencies.

## Repo map

- `src/clawpass_server/core/`: product contracts, persistence, webhook behavior
- `src/clawpass_server/api/`: route layer
- `src/clawpass_server/web/`: built-in browser UI and operator dashboard
- `src/clawpass_sdk_py/`: Python SDK
- `ts-sdk/`: TypeScript SDK
- `tests/`: regression coverage
- `docs/`: human-facing docs
- `autoresearch/` and `scripts/repo_autoresearch_eval.py`: bounded improvement harness

## Source of truth

When documenting or changing behavior, prefer these files in order:
1. `src/clawpass_server/core/service.py`
2. `src/clawpass_server/core/webhooks.py`
3. `src/clawpass_server/api/routes.py`
4. tests under `tests/`
5. SDK surfaces
6. docs

Do not document features that are not implemented in those surfaces.

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

## Validation

Minimum meaningful validation for runtime changes:

```bash
source .venv/bin/activate
pytest -q
python3 scripts/check_sdk_roundtrip.py
npx -y -p tsx tsx scripts/check_ts_sdk_roundtrip.ts
npx -y -p typescript tsc --noEmit ts-sdk/src/index.ts
node --check src/clawpass_server/web/app.js
```

Regenerate OpenAPI when routes or schemas changed:

```bash
source .venv/bin/activate
python - <<'PY' > docs/openapi.json
import json
from clawpass_server.app import create_app
app = create_app()
print(json.dumps(app.openapi(), indent=2))
PY
```

## Autoresearch

Use the repo-local harness for bounded improvement loops. Keep changed files inside the allowed surface declared in `autoresearch/benchmark-pack.*.json`.

Fast pack:

```bash
source .venv/bin/activate
python3 scripts/repo_autoresearch_eval.py \
  --pack autoresearch/benchmark-pack.fast.json \
  --diff-ref HEAD \
  --results-tsv state/autoresearch/results.tsv \
  --description "candidate"
```

Full pack:

```bash
source .venv/bin/activate
python3 scripts/repo_autoresearch_eval.py \
  --pack autoresearch/benchmark-pack.full.json \
  --diff-ref HEAD \
  --results-tsv state/autoresearch/results.tsv \
  --description "candidate-full"
```

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
