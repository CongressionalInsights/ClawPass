# Contributing to ClawPass

This repo is small enough that the fastest way to contribute well is to stay close to the actual product seams: approval request contracts, verification methods, webhook delivery behavior, operator workflows, and SDK parity.

## What ClawPass is

ClawPass is an approval service for high-risk operations. It exposes:
- an HTTP API for approval requests and decision flows,
- a built-in browser UI for approver onboarding and operator webhook triage,
- a Python SDK and a TypeScript SDK,
- a repo-local autoresearch harness for bounded improvement loops.

The current product surface is intentionally narrow. Prefer additive, reviewable changes over broad rework.

## Development setup

### Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

ClawPass requires Python `>=3.12`.

### Local run

```bash
source .venv/bin/activate
clawpass-server
```

Open:
- UI: `http://localhost:8081`
- API docs: `http://localhost:8081/docs`
- Health: `http://localhost:8081/healthz`

### Docker run

```bash
docker compose up --build
```

## Repo map

- `src/clawpass_server/`: FastAPI app, core service logic, adapters, UI assets
- `src/clawpass_sdk_py/`: Python SDK
- `ts-sdk/`: TypeScript SDK
- `tests/`: service, API, and SDK regression coverage
- `examples/`: producer integration examples
- `docs/`: human-facing documentation
- `autoresearch/`: repo-local outer-loop control files
- `scripts/`: validation helpers and autoresearch evaluator

## Key product contracts

### Approval lifecycle

Approval requests move through `PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, or `CANCELLED`.

When changing this lifecycle, update all of the following together:
- API schemas and routes
- service behavior
- emitted webhook events
- Python SDK and TypeScript SDK
- tests
- docs

### Decision methods

Supported approval methods are:
- `webauthn`
- `ledger_webauthn`
- `ethereum_signer`

High-risk approvals require at least one non-ledger passkey on the approver account. Do not document or implement a bypass unless the product contract explicitly changes.

### Webhook subsystem

Webhook behavior is now a first-class product surface. It includes:
- queued deliveries
- lease-backed recovery
- immediate retry for transient failures
- scheduled retry with jitter
- dead-letter marking
- endpoint-level auto-mute / circuit-breaker behavior
- operator prune history
- manual redelivery and retry-now actions

If you change webhook behavior, update:
- `src/clawpass_server/core/webhooks.py`
- `src/clawpass_server/core/service.py`
- `src/clawpass_server/web/`
- SDK surfaces
- operator docs

## Validation

Run the full repo checks before opening or merging a meaningful change.

### Core checks

```bash
source .venv/bin/activate
pytest -q
python3 scripts/check_sdk_roundtrip.py
npx -y -p tsx tsx scripts/check_ts_sdk_roundtrip.ts
npx -y -p typescript tsc --noEmit ts-sdk/src/index.ts
node --check src/clawpass_server/web/app.js
```

### OpenAPI export

Regenerate the checked-in OpenAPI file from the repo-local virtualenv:

```bash
source .venv/bin/activate
python - <<'PY' > docs/openapi.json
import json
from clawpass_server.app import create_app
app = create_app()
print(json.dumps(app.openapi(), indent=2))
PY
```

Do not claim OpenAPI or SDK surfaces changed cleanly if `docs/openapi.json` was not regenerated when routes or schemas changed.

## Autoresearch workflow

The repo-local autoresearch harness is for bounded improvement loops, not arbitrary repo churn.

### Fast pack

```bash
source .venv/bin/activate
python3 scripts/repo_autoresearch_eval.py \
  --pack autoresearch/benchmark-pack.fast.json \
  --diff-ref HEAD \
  --results-tsv state/autoresearch/results.tsv \
  --description "candidate"
```

### Full pack

```bash
source .venv/bin/activate
python3 scripts/repo_autoresearch_eval.py \
  --pack autoresearch/benchmark-pack.full.json \
  --diff-ref HEAD \
  --results-tsv state/autoresearch/results.tsv \
  --description "candidate-full"
```

The evaluator enforces allowed-surface scope and includes untracked files in the diff check. Keep experiments bounded.

## Documentation expectations

ClawPass docs should describe only implemented behavior.

When changing product behavior, update the affected docs in the same PR. In practice that usually means some combination of:
- `README.md`
- `docs/operator-runbook.md`
- `docs/integration-guide.md`
- `docs/webhook-operations.md`
- `docs/architecture.md`
- SDK README files

## Pull request expectations

A good PR for this repo is:
- bounded to one contract seam,
- explicit about user-visible behavior changes,
- validated with the repo checks above,
- synchronized across API, SDK, tests, and docs.

If a change is docs-only, say so explicitly. If a change affects runtime behavior, do not merge it with stale docs.
