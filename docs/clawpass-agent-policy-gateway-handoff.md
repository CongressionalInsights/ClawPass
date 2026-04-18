# ClawPass Self-Hosted Agent Policy Gateway Handoff

Date: 2026-04-17

This report assumes these product decisions are already made:

- ClawPass is OSS and self-hosted first.
- The first supported identity model is single-admin deployment.
- ClawPass is the human approval control boundary for risky agent execution, not only a helpful approval widget.

The goal is to turn the current repo into a concrete product path toward: install the service, bootstrap admin access, enroll passkey or Ledger from any device, issue producer credentials, and put ClawPass in front of risky agent actions as the authenticated hold and release point.

## 1. Current-State Assessment

### Runtime and storage as implemented today

ClawPass is currently one FastAPI process that serves the HTTP API and the built-in web UI from the same app. `src/clawpass_server/app.py` wires `FastAPI`, mounts the static web assets, initializes SQLite, starts webhook recovery, and serves `/`, `/docs`, and `/healthz`. There is no separate auth service, worker process, or external dependency beyond SQLite and outbound HTTP for webhooks.

Persistence is SQLite with WAL enabled and implicit startup migrations in `src/clawpass_server/core/database.py`. The schema already has durable approval and operator primitives: `approval_requests`, `decision_challenges`, `approvers`, `webauthn_credentials`, `ethereum_signers`, `webhook_events`, `webhook_endpoint_controls`, and `audit_events`.

Deployment support is still local and Docker oriented. The repo ships a slim Python `Dockerfile`, a single-service `docker-compose.yml`, and a local `.venv` development path. Compose binds `8081`, stores SQLite under `/data/clawpass.db`, and assumes localhost WebAuthn defaults.

### Onboarding and approval UX as implemented today

The current UI in `src/clawpass_server/web/index.html` and `src/clawpass_server/web/app.js` is a single page that combines onboarding, approval request creation, approver settings, and webhook operations. The onboarding flow is real in the sense that it exercises the actual WebAuthn and Ledger enrollment APIs, but it is still internal-quality in product terms:

- It creates or resolves approver identity directly from `email`, `display_name`, or `approver_id` request fields.
- It has no authenticated admin or operator session.
- It has no bootstrap state, invitation model, login screen, or role separation.
- It assumes the person sitting at the page can type an email and immediately begin enrollment.

The approval decision flow is also real but not yet productized. `POST /v1/approval-requests/{id}/decision/start` takes an arbitrary `approver_id` from the client, and `POST /decision/complete` finalizes the decision after WebAuthn or Ethereum verification. That proves out the cryptographic approval core, but not a public-grade access model.

### Webhook and operator surface as implemented today

The webhook subsystem is already one of the most production-shaped parts of the repo. `src/clawpass_server/core/webhooks.py` and `src/clawpass_server/core/service.py` implement durable event recording, lease-backed delivery, retry scheduling, dead-lettering, endpoint mute controls, redelivery, retry-now, prune history, and aggregate health summaries. The operator runbook and webhook docs match that functionality.

Operator visibility is also strong for the current maturity level. The UI exposes backlog health, attention filters, endpoint state, mute and unmute actions, prune history, and failed-event triage. The service also emits append-only audit events for enrollment, approval lifecycle transitions, and operator-style webhook actions.

### SDK and integration surface as implemented today

The producer surface is intentionally thin and already maps well to an agent policy gateway model:

- `POST /v1/approval-requests`
- `GET /v1/approval-requests`
- `GET /v1/approval-requests/{id}`
- `POST /v1/approval-requests/{id}/cancel`
- webhook summary and event inspection endpoints

The Python SDK in `src/clawpass_sdk_py/client.py` and the TypeScript SDK in `ts-sdk/src/index.ts` are simple HTTP mirrors. That is good for productization because there is not much client-side abstraction to unwind. It is also a gap because neither SDK provides a first-class producer-auth contract yet. The TypeScript client can accept arbitrary headers, but not a defined API-key model. The Python client does not currently expose a headers or auth configuration surface at all.

### Missing product-critical layers

The repo does not yet have the layers required for a real self-hosted product:

- No admin bootstrap state.
- No authenticated admin or operator session model.
- No producer or agent machine authentication.
- No API-key issuance, rotation, revocation, or producer identity table.
- No public-grade invitation or enrollment flow for approvers.
- No approval links or approval UI designed for people arriving from outside local development.
- No minimum external deployment story beyond local Docker and localhost WebAuthn defaults.
- No route-level separation between anonymous setup, authenticated operator actions, producer actions, and human approval actions.

The generated API surface also reflects that gap. The current OpenAPI export has no auth scheme because the API is effectively open once the service is reachable.

### Production-shaped core vs demo or internal-quality surfaces

Already production-shaped enough to keep and build on:

- Approval request lifecycle and state machine.
- Hash-bound decision envelopes with nonce and expiry.
- Passkey, Ledger security-key, and Ethereum signer verification paths.
- Append-only audit events.
- Durable webhook operations and operator health visibility.
- Thin Python and TypeScript SDKs.

Still demo or internal quality and should not be treated as the final product shape:

- Anonymous onboarding by email entry.
- Anonymous operator dashboard.
- Anonymous approval-request creation.
- Mixed root page that combines setup, approval demo, and operations.
- Localhost-first deployment assumptions.
- Lack of any admin, producer, or approver session boundary.

## 2. Target Product Definition

ClawPass should be defined as a self-hosted approval control plane for agentic systems. It is not a general workflow engine and it is not a multi-tenant SaaS first. Its job is to be the authenticated human control boundary that risky agent actions must cross before execution continues.

The primary user roles are:

- Deploy admin or operator. Owns installation, bootstrap, producer key issuance, operator settings, and system health.
- Human approver. Reviews risky actions and approves or denies them with passkey or Ledger.
- Producer or agent client. Submits gated actions, pauses execution, observes final state, and only resumes from an authenticated ClawPass decision path.

The core product promise is:

- Agents can propose risky actions.
- ClawPass can put those actions into a durable pending state.
- Humans can approve or deny using passkey or Ledger.
- The producer resumes execution only after it re-checks an approved ClawPass record from an authenticated producer context.

In other words, ClawPass becomes the policy gateway for execution. The agent does not “ask nicely and continue anyway.” It must hold on ClawPass state and only proceed when ClawPass releases the action.

Non-goals for this productization pass:

- Multi-tenant SaaS-first design.
- Consumer or social account identity.
- Enterprise reporting or approval analytics as the primary product.
- Turning ClawPass into the thing that executes shell commands or jobs itself in P0.

## 3. Future Architecture Recommendation

### Admin bootstrap and admin auth

Recommendation: ClawPass should have an explicit uninitialized state and a single secure bootstrap path.

The service should start in one of two modes:

- `uninitialized`: no admin exists yet.
- `initialized`: at least one admin exists, so bootstrap is disabled.

The first-run bootstrap should require possession of a bootstrap secret supplied by the installer, not merely network reachability. The concrete direction is:

- Add `CLAWPASS_BOOTSTRAP_TOKEN` and `CLAWPASS_BOOTSTRAP_TOKEN_FILE`.
- Prefer `_FILE` in Docker or VM docs so the token can come from a mounted secret.
- Expose `GET /setup` only while no admin exists.
- `POST /v1/setup/bootstrap/start` takes `bootstrap_token`, `email`, and `display_name`, validates the one-time bootstrap token, and returns a WebAuthn registration challenge for the first admin passkey.
- `POST /v1/setup/bootstrap/complete` consumes the bootstrap session, creates the admin account, creates the matching approver identity, registers the first non-Ledger passkey, marks the instance initialized, and creates an authenticated admin session.

Later admin access should be passkey-first and session-cookie based:

- `POST /v1/auth/admin/login/start`
- `POST /v1/auth/admin/login/complete`
- Session cookie should be `HttpOnly`, `Secure`, and `SameSite=Lax`.
- State-changing browser requests should use CSRF protection.

The admin should also be the first approver by default. That keeps the single-admin deployment model simple and avoids a second identity bootstrap problem.

### Producer and agent auth

Recommendation: producer and agent clients should authenticate with per-producer API keys, not reused admin sessions and not ad hoc shared secrets in request metadata.

The concrete model is:

- Add a `producers` table with stable `producer_id`, display name, description, created_at, revoked_at.
- Add a `producer_api_keys` table with `key_id`, `producer_id`, key hash, optional label, created_at, last_used_at, revoked_at.
- API key format should be `cpk_<public_key_id>.<secret>`.
- Store only the key hash server-side. Return the full key once at creation time.
- Producer API calls use `Authorization: Bearer <api_key>`.
- Producer keys authenticate machine clients only. They do not open the operator UI.

Producer identity should stop depending on caller-supplied `requester_id`. The request model should become:

- `producer_id`: derived from the authenticated API key.
- `requester_id`: optional producer-local subject or agent-run identity.
- `action_ref`: optional producer-side reference.

That identity should appear in approval records, webhooks, and audit logs so the operator can see which producer created the gated action and which end-user or agent-run it was acting on behalf of.

### Approval access model

Recommendation: the default single-admin deployment should treat the bootstrap admin as the first approver and support admin-issued approver invites when a second approver is needed.

The concrete path is:

- P0: admin bootstrap creates the first approver automatically.
- P1: admin can create invite links for approver-only identities.
- Invite links should be time-limited and single-use.
- Enrollment should always require a non-Ledger passkey first.
- Ledger enrollment remains optional after the non-Ledger passkey baseline is satisfied.

Passkey and Ledger enrollment should work across desktop and mobile through authenticated enrollment surfaces, not by typing arbitrary identity fields into a public page:

- `GET /settings/security` for a logged-in admin or approver.
- `GET /invites/{token}` for a pending approver invite.
- Passkey enrollment should use the current-device WebAuthn prompt, with a visible “use another device” path when cross-device passkeys are needed.
- Ledger as WebAuthn security key should be offered where browser support exists.
- Ledger Ethereum signer should be a secondary option, exposed only after the account already has at least one non-Ledger passkey.

Approval itself should use authenticated session context, not client-supplied `approver_id`. A human opening an approval link should log in or arrive from an invite, then the approval UI should call decision start and complete using the session-derived approver identity.

### Deployment model

Recommendation: support exactly two self-hosted deployment targets in the next phase.

- Local evaluation on Docker Desktop or local Python.
- Single Linux VM deployment with Docker Compose, a persistent volume, and HTTPS termination through Caddy.

That is enough for OSS self-hosted P0 and P1 and avoids premature platform spread.

SQLite remains acceptable for P0 and P1 if and only if the deployment stays single-instance. That means:

- one app instance
- one local SQLite file on persistent disk
- webhook recovery loop stays in the same process

Postgres becomes required when any of these become true:

- more than one app replica
- separate background worker processes
- HA or managed database expectations
- broader workspace or team support that requires stronger concurrency guarantees and backup tooling

The minimum external deployment story should therefore be:

- public HTTPS URL
- stable `CLAWPASS_BASE_URL`
- matching WebAuthn `RP_ID` and expected origins
- persistent disk for SQLite
- reverse proxy or sidecar for TLS
- documented backup and restore for the SQLite file

Do not market or document multi-instance Compose or Kubernetes until Postgres exists.

### Execution-control integration

Recommendation: keep the existing approval-request resource as the gateway contract, then wrap it in producer SDK helpers that make the hold and resume semantics explicit.

The required producer loop is:

1. Producer canonicalizes the risky action payload and computes `action_hash`.
2. Producer creates an approval request under producer API-key auth.
3. Producer enters a hold state and persists the returned `request_id`.
4. Human approves or denies through ClawPass.
5. Producer receives a webhook or polling result.
6. Producer re-fetches the approval request from ClawPass under producer auth.
7. Producer verifies `status`, `action_hash`, `producer_id`, and `request_id`.
8. Producer executes only on `APPROVED`. It aborts on `DENIED`, `EXPIRED`, or `CANCELLED`.

Polling, webhooks, and SDKs should fit together like this:

- Polling remains the source-of-truth fallback.
- Webhooks are the fast signal for waking a held agent or workflow.
- SDKs should add `createGatedAction(...)`, `awaitFinalDecision(...)`, and `verifyApprovedAction(...)` helpers, but those helpers should still operate on the approval-request resource.

This keeps ClawPass as the policy gateway without forcing P0 to invent a brand-new execution protocol.

## 4. Frictionless Onboarding Plan

### Intended first-run journey

1. Install and start the service with Docker Compose or local Python.
2. Open the service URL. If the instance is not initialized, ClawPass shows `/setup` instead of the normal app.
3. Enter the installer-provided bootstrap token.
4. Enter admin email and display name.
5. Register the first admin passkey on desktop or mobile.
6. Land in an authenticated operator session.
7. Prompt immediately for a second recovery path. Offer “add another passkey on this device,” “use another device,” and “do this later with warning.”
8. From the operator app, create the first producer.
9. Issue the first producer API key and show it once, with copy instructions and SDK examples.
10. Optionally enroll Ledger as security key or Ethereum signer from authenticated settings.
11. Submit the first gated action from a producer example or SDK snippet.
12. Open the approval link on desktop or mobile, approve or deny, and watch the producer resume or abort accordingly.

### Current UX vs target UX

Current UX:

- Open `/`.
- Type an email and display name into a public page.
- Create a passkey.
- Optionally create demo approval requests in the same page.
- Use webhook ops from the same page with no authenticated session.

Target UX:

- Open `/setup` only on uninitialized installs.
- Securely bootstrap the first admin with a one-time installer-controlled secret.
- Create a real admin session and first approver identity in one flow.
- Move onboarding, operator controls, producer management, and approval into distinct authenticated surfaces.
- Issue producer credentials before any external producer integration begins.
- Use approval links and authenticated approval UI rather than a mixed demo panel.

### Missing steps that make current onboarding non-public

- No initialization gate.
- No bootstrap secret.
- No login or admin session.
- No producer creation or API-key issuance UI.
- No authenticated approval links.
- No invite flow for non-admin approvers.
- No clear “you are enrolling recovery” versus “you are approving a live request” UX separation.
- No public deployment guidance for TLS, RP ID, origin, and persistent storage.

### Recommended product surfaces

The public-grade UI should split into these screens:

- `/setup` for first-run bootstrap only.
- `/login` for admin or approver passkey login.
- `/app` for authenticated operator workflow.
- `/settings/security` for passkey and Ledger enrollment.
- `/approve/{request_id}` for human review and final decision.

That split is the main UX move that turns today’s strong internal wiring into a real product.

## 5. Phased Roadmap

### P0: Secure bootstrap and basic agent gating

User-visible outcome: a self-hosted admin can install ClawPass, bootstrap the first admin passkey, create a producer API key, submit an authenticated approval request, and hold agent execution until approve or deny.

Required product and design decisions: bootstrap is token-gated, admin is the first approver, producer auth is API-key based, operator UI is session protected, producer identity is derived from auth, and the deployment target is single-instance self-hosted.

Backend changes: add admin, admin-session, producer, and producer-key persistence; add bootstrap state; add session issuance and validation; add request-level `producer_id`; enforce auth on routes; stop creating approvers from anonymous input outside bootstrap or invite flows.

API and SDK changes: add bootstrap start and complete endpoints; add admin login endpoints; require producer auth on producer routes; add producer-management endpoints for key issuance; update approval-request response and webhook payload to include `producer_id`; add Python and TypeScript SDK support for `apiKey`.

Docs and ops changes: add install guide for local Docker and single-VM Compose plus Caddy; document bootstrap token handling; document backup of SQLite; document producer setup and agent gating quickstart.

Validation criteria: a fresh install can bootstrap once and only once; the operator UI is inaccessible without an admin session; producer routes reject missing or invalid API keys; a sample producer can create a request, wait, and execute only after an approved re-fetch; approval and operator audit logs show producer and approver identity.

### P1: Public-grade enrollment and execution UX

User-visible outcome: passkey and Ledger enrollment feel intentional on desktop and mobile, approval links are safe to send outside local development, and producer integration guidance is clean enough for external adopters.

Required product and design decisions: approval links become first-class, secondary approver invites are supported, mobile passkey flow is a designed path rather than an incidental browser behavior, and Ledger UX clearly separates security-key and Ethereum-signer modes.

Backend changes: add approver invite records and invite consumption; add authenticated approval-view route support; add session-derived decision start and complete; add better approval context rendering and device capability handling.

API and SDK changes: add invite endpoints; add approval-link metadata endpoint for the approval page; add SDK helpers for hold, wait, and verify; add more explicit webhook delivery guidance for waking held agents.

Docs and ops changes: add public-grade passkey and Ledger setup guides; add screenshots or flow diagrams for desktop and mobile approval; add a producer integration cookbook for polling, callbacks, and idempotent resume.

Validation criteria: an invited approver can enroll from a phone or laptop without manual identity entry; approval links require authenticated approver context; the operator can issue a producer key and follow a documented end-to-end example without local-dev assumptions; Ledger flows fail clearly when the client environment does not support them.

### P2: Hardening and scale path

User-visible outcome: the self-hosted product has safer deployment defaults, clearer migration paths, richer policy controls, and a defined route to broader team support without redesigning the core.

Required product and design decisions: define the SQLite to Postgres migration boundary, define the first policy controls beyond “approval required,” and define what minimal team support means without drifting into SaaS multi-tenancy.

Backend changes: add database abstraction for Postgres readiness; add policy objects or rulesets tied to producer or action type; add stronger audit filtering and recovery tooling; add safer secret handling and config validation at startup.

API and SDK changes: add policy-scoped producer configuration; add versioned auth and config surfaces where needed; add migration-safe schema evolution for `producer_id`, policy metadata, and future approver roles.

Docs and ops changes: add Postgres deployment docs; add migration guide from SQLite; add secret rotation and key rotation runbooks; add safer reverse-proxy and TLS defaults.

Validation criteria: a documented migration path exists from single-instance SQLite to Postgres; multiple producers can be managed safely; operator auth and producer auth can be rotated without downtime; policy rules can gate by action type or risk without breaking existing producers.

## 6. Recommended Future Interfaces

### Admin bootstrap entrypoint

Use this exact shape:

- `GET /setup`
- `POST /v1/setup/bootstrap/start`
- `POST /v1/setup/bootstrap/complete`

`/setup` is available only when the instance is uninitialized. Bootstrap requires `CLAWPASS_BOOTSTRAP_TOKEN` or `CLAWPASS_BOOTSTRAP_TOKEN_FILE` to have been provided at install time.

### Authenticated operator access model

Use passkey-authenticated browser sessions:

- `POST /v1/auth/admin/login/start`
- `POST /v1/auth/admin/login/complete`
- `POST /v1/auth/logout`

Operator-only pages live under `/app` and `/settings/*`. Webhook operations, producer management, and future config pages require an admin session cookie.

### Producer and agent API-key auth surface

Use:

- `Authorization: Bearer cpk_<public_key_id>.<secret>`

Producer-facing routes require a valid producer key:

- `POST /v1/approval-requests`
- `GET /v1/approval-requests/{id}`
- `GET /v1/approval-requests?status=...`
- producer-scoped webhook reconciliation routes if exposed

Admin routes create and revoke those keys:

- `POST /v1/operator/producers`
- `POST /v1/operator/producers/{producer_id}/keys`
- `POST /v1/operator/producers/{producer_id}/keys/{key_id}/revoke`

### Producer identity and audit representation

Approval requests should carry both machine identity and caller context:

- `producer_id`: authenticated ClawPass producer identity
- `requester_id`: optional producer-local end-user, agent-run, or workflow identity
- `action_ref`: optional producer-side business reference

Webhook payloads and audit events should include `producer_id` so operator review never depends on reconstructing it from request metadata.

### First-run install and setup flow

Self-hosted install should require these minimum settings:

- `CLAWPASS_BASE_URL`
- `CLAWPASS_EXPECTED_ORIGINS`
- `CLAWPASS_RP_ID`
- `CLAWPASS_DB_PATH`
- `CLAWPASS_BOOTSTRAP_TOKEN` or `CLAWPASS_BOOTSTRAP_TOKEN_FILE`
- `CLAWPASS_SESSION_SECRET` or `CLAWPASS_SESSION_SECRET_FILE`
- `CLAWPASS_WEBHOOK_SECRET` or `CLAWPASS_WEBHOOK_SECRET_FILE`

The documented public deployment should be a single-host Compose stack with Caddy and a persistent volume.

### Approval-request creation under authenticated producer context

Keep the existing route and make auth mandatory:

- `POST /v1/approval-requests`

Request body should keep:

- `request_id`
- `action_type`
- `action_hash`
- `action_ref`
- `requester_id`
- `risk_level`
- `metadata`
- `expires_at`
- `callback_url`

The server should derive `producer_id` from the API key and persist it on the approval request. The response and webhook payload should return it.

### Human approval flow for passkey and Ledger on mobile and desktop

Use a dedicated approval surface:

- `GET /approve/{request_id}`

The page loads the approval context, requires approver authentication, and then offers:

- Approve with passkey
- Deny with passkey
- Approve with Ledger security key when available
- Approve with Ledger Ethereum signer when enrolled and available

The browser UI should call:

- `POST /v1/approval-requests/{id}/decision/start`
- `POST /v1/approval-requests/{id}/decision/complete`

The key change is that the server derives the approver identity from the authenticated session. `approver_id` should not be accepted from arbitrary public clients once the productized flow exists.

### Deployment configuration surface for self-hosted installs

P0 and P1 should document one supported deployment shape:

- one app instance
- one SQLite file on persistent disk
- one HTTPS hostname
- one reverse proxy or TLS sidecar

The docs should explicitly say:

- SQLite is supported only for single-instance deployments.
- Postgres is required before multi-instance or HA deployment.
- WebAuthn `RP_ID` and origin must match the public hostname.
- Backup and restore procedures for the database file are mandatory.

## Final recommendation

Do not reposition ClawPass as a generic approval helper anymore. Productize it as a self-hosted agent policy gateway with three hard boundaries:

- admin bootstrap and operator control are authenticated
- producer request creation is authenticated
- risky execution resumes only after a producer re-checks an approved ClawPass decision

That direction preserves the strongest parts of the current repo, avoids premature SaaS or enterprise drift, and gives the next implementation pass a clean P0 target.
