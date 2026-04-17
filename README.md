# ClawPass

ClawPass is a standalone approval platform for high-risk operations.

It supports dual-mode cryptographic approvals:
- Passkeys (WebAuthn) as a first-class path
- Ledger-backed approval via security-key WebAuthn and Ethereum typed signatures

## Features

- Durable approval intent lifecycle (`PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `CANCELLED`)
- Hash-bound decision verification with nonce + expiry controls
- Policy engine with default single-approver model
- High-risk guard: request cannot be approved if approver has zero non-ledger passkeys
- Append-only audit events and webhook delivery log
- Built-in onboarding UI for mobile + desktop passkey creation
- HTTP API + Python SDK + TypeScript SDK

## Quick Start (Docker-first)

```bash
cd clawpass
docker compose up --build
```

Open:
- UI: <http://localhost:8081>
- API docs: <http://localhost:8081/docs>
- Health: <http://localhost:8081/healthz>

## Local Dev

```bash
cd clawpass
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
clawpass-server
```

## Core API

- `POST /v1/webauthn/register/start`
- `POST /v1/webauthn/register/complete`
- `POST /v1/approval-requests`
- `GET /v1/approval-requests`
- `POST /v1/approval-requests/{id}/cancel`
- `POST /v1/approval-requests/{id}/decision/start`
- `POST /v1/approval-requests/{id}/decision/complete`
- `POST /v1/signers/ethereum/challenge`
- `POST /v1/signers/ethereum/verify`
- `GET /v1/approvers/{approver_id}/summary`
- `GET /v1/webhook-events`
- `POST /v1/webhook-events/{id}/redeliver`

## Docs

- [Passkey Guide (mobile + desktop)](docs/passkey-guide.md)
- [Ledger Setup Guide](docs/ledger-setup.md)
- [Threat Model](docs/threat-model.md)
- [Recovery Model](docs/recovery-model.md)
- [Operator Runbook](docs/operator-runbook.md)
- [OpenAPI Export](docs/openapi.md)

## Example Integrations

- [Scotty adapter](examples/scotty_adapter.py)
- [Generic FastAPI producer](examples/generic_fastapi_producer.py)

## License

Apache-2.0
