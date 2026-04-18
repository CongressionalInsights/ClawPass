# ClawPass

ClawPass is a standalone approval platform for high-risk operations.

P0 product shape:
- self-hosted first
- single-admin bootstrap first
- producer and agent clients authenticate with API keys
- humans approve or deny from an authenticated control path using passkeys or Ledger-backed methods

It supports dual-mode cryptographic approvals:
- Passkeys (WebAuthn) as a first-class path
- Ledger-backed approval via security-key WebAuthn and Ethereum typed signatures

## Features

- Durable approval intent lifecycle (`PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `CANCELLED`)
- Hash-bound decision verification with nonce + expiry controls
- Policy engine with default single-approver model
- High-risk guard: request cannot be approved if approver has zero non-ledger passkeys
- First-run `/setup` bootstrap for the initial admin passkey
- Cookie-backed human session with admin overlay for `/app` and approval links
- Approver invite and enrollment flow at `/invites/{token}`
- Producer registry with one-time-visible API keys
- Append-only audit events and webhook delivery log
- Lease-backed webhook recovery and operator health summary
- Built-in onboarding UI for desktop + mobile passkey creation, approval, and Ledger enrollment
- HTTP API + Python SDK + TypeScript SDK

## Quick Start (Docker-first)

```bash
cd clawpass
export CLAWPASS_BASE_URL=http://localhost:8081
export CLAWPASS_BOOTSTRAP_TOKEN=replace-with-a-long-random-bootstrap-token
export CLAWPASS_SESSION_SECRET=replace-with-a-long-random-session-secret
docker compose up --build
```

Open:
- Setup or login UI: <http://localhost:8081>
- API docs: <http://localhost:8081/docs>
- Health: <http://localhost:8081/healthz>

First-run flow:
1. Open `/setup`.
2. Enter `CLAWPASS_BOOTSTRAP_TOKEN`.
3. Enroll the first admin passkey.
4. Land in `/app`.
5. Create a producer and issue its API key.
6. Optionally invite another approver and let them enroll from `/invites/{token}` on desktop or mobile.
7. Give the producer API key to the producer SDK or HTTP client.

For anything beyond localhost:
- serve ClawPass over HTTPS
- keep `CLAWPASS_BASE_URL`, `CLAWPASS_EXPECTED_ORIGIN`, and `CLAWPASS_RP_ID` aligned to the public hostname
- persist `/data/clawpass.db`
- supply secrets through env files or secret files instead of inline values
- run a single app instance against that SQLite file

## Local Dev

```bash
cd clawpass
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
export CLAWPASS_BASE_URL=http://localhost:8081
export CLAWPASS_BOOTSTRAP_TOKEN=dev-bootstrap-token
export CLAWPASS_SESSION_SECRET=dev-session-secret
clawpass-server
```

## Core API

Most integrations use a small core of the API surface:

Bootstrap and auth:
- `GET /v1/setup/status`
- `POST /v1/setup/bootstrap/start`
- `POST /v1/setup/bootstrap/complete`
- `POST /v1/auth/login/start`
- `POST /v1/auth/login/complete`
- `GET /v1/auth/session`

Approver invite and approval entry:
- `GET /v1/approval-links/{id}`
- `GET /v1/invites/{token}`
- `POST /v1/invites/{token}/start`
- `POST /v1/invites/{token}/complete`

Producer-facing approval flow:
- `POST /v1/approval-requests`
- `GET /v1/approval-requests`
- `GET /v1/approval-requests/{id}`
- `POST /v1/approval-requests/{id}/cancel`

Human decision and admin operator flow:
- `POST /v1/approval-requests/{id}/decision/start`
- `POST /v1/approval-requests/{id}/decision/complete`
- `GET /v1/operator/approvers`
- `POST /v1/operator/approver-invites`
- `POST /v1/operator/producers`
- `POST /v1/operator/producers/{producer_id}/keys`
- `GET /v1/webhook-summary`

Use the interactive API browser at `/docs` for the complete route list.

## Docs

- [Architecture Overview](docs/architecture.md)
- [Integration Guide](docs/integration-guide.md)
- [Webhook Operations](docs/webhook-operations.md)
- [Passkey Guide (mobile + desktop)](docs/passkey-guide.md)
- [Ledger Setup Guide](docs/ledger-setup.md)
- [Threat Model](docs/threat-model.md)
- [Recovery Model](docs/recovery-model.md)
- [Operator Runbook](docs/operator-runbook.md)
- [OpenAPI Export](docs/openapi.md)
- [Contributor Guide](CONTRIBUTING.md)
- [Agent Guide](AGENTS.md)

## Example Integrations

- [Scotty adapter](examples/scotty_adapter.py)
- [Generic FastAPI producer](examples/generic_fastapi_producer.py)

## License

Apache-2.0
