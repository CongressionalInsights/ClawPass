from __future__ import annotations

import json
import sqlite3
from datetime import timedelta, timezone
from typing import Any

from fastapi import HTTPException

from clawpass_server.adapters.ethereum_adapter import EthereumAdapter
from clawpass_server.adapters.webauthn_adapter import WebAuthnAdapter
from clawpass_server.core.auth import (
    AdminSessionPrincipal,
    ProducerPrincipal,
    extract_bearer_token,
    hash_secret,
    make_api_key,
    secret_matches,
    split_api_key,
)
from clawpass_server.core.audit import AuditLogger
from clawpass_server.core.config import Settings
from clawpass_server.core.constants import (
    APPROVAL_STATUS_APPROVED,
    APPROVAL_STATUS_CANCELLED,
    APPROVAL_STATUS_DENIED,
    APPROVAL_STATUS_EXPIRED,
    APPROVAL_STATUS_PENDING,
    DECISION_APPROVE,
    EVENT_APPROVAL_APPROVED,
    EVENT_APPROVAL_CANCELLED,
    EVENT_APPROVAL_DENIED,
    EVENT_APPROVAL_EXPIRED,
    EVENT_APPROVAL_PENDING,
    METHOD_ETHEREUM_SIGNER,
    METHOD_LEDGER_WEBAUTHN,
    METHOD_WEBAUTHN,
    VALID_APPROVAL_STATUSES,
    VALID_RISK_LEVELS,
    VALID_WEBHOOK_EVENT_STATUSES,
    WEBHOOK_STATUS_DELIVERED,
    WEBHOOK_STATUS_FAILED,
    WEBHOOK_STATUS_QUEUED,
    WEBHOOK_STATUS_SKIPPED,
)
from clawpass_server.core.database import Database
from clawpass_server.core.policy import PolicyEngine
from clawpass_server.core.schemas import (
    AdminLoginCompleteRequest,
    AdminLoginStartResponse,
    AdminSessionResponse,
    ApprovalLinkResponse,
    ApprovalRequestResponse,
    ApproverIdentityIn,
    ApproverInviteCreateRequest,
    ApproverInviteResponse,
    ApproverResponse,
    ApproverSummary,
    BootstrapCompleteRequest,
    BootstrapStartRequest,
    BootstrapStartResponse,
    BootstrapStatusResponse,
    CreateApprovalRequest,
    DecisionCompleteRequest,
    DecisionStartRequest,
    DecisionStartResponse,
    EthereumSignerChallengeRequest,
    EthereumSignerChallengeResponse,
    EthereumSignerVerifyRequest,
    EthereumSignerVerifyResponse,
    LoginStartRequest,
    ProducerCreateRequest,
    ProducerKeyCreateRequest,
    ProducerKeyResponse,
    ProducerResponse,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterCompleteResponse,
    WebAuthnRegisterStartRequest,
    WebAuthnRegisterStartResponse,
    WebhookEndpointControlResponse,
    WebhookEndpointMuteRequest,
    WebhookDeliverySummary,
    WebhookEndpointSummary,
    WebhookEventResponse,
    WebhookPruneHistoryEntry,
    WebhookPruneResult,
    WebhookEndpointUnmuteRequest,
)
from clawpass_server.core.utils import (
    add_minutes_iso,
    add_seconds_iso,
    json_dumps,
    parse_iso,
    stable_id,
    token_urlsafe,
    utc_now,
    utc_now_iso,
)
from clawpass_server.core.webhooks import WebhookDispatcher


class ClawPassService:
    def __init__(self, *, settings: Settings, db: Database, webauthn: WebAuthnAdapter, ethereum: EthereumAdapter) -> None:
        self._settings = settings
        self._db = db
        self._policy = PolicyEngine()
        self._audit = AuditLogger(db)
        self._webauthn = webauthn
        self._ethereum = ethereum
        self._webhooks = WebhookDispatcher(db, settings)

    def is_initialized(self) -> bool:
        row = self._db.fetchone("SELECT id FROM admins LIMIT 1")
        return bool(row)

    def get_bootstrap_status(self) -> BootstrapStatusResponse:
        return BootstrapStatusResponse(
            initialized=self.is_initialized(),
            bootstrap_configured=bool(self._settings.bootstrap_token),
        )

    def start_bootstrap(self, payload: BootstrapStartRequest) -> BootstrapStartResponse:
        if self.is_initialized():
            raise HTTPException(status_code=400, detail="ClawPass is already initialized.")
        if not self._settings.bootstrap_token:
            raise HTTPException(status_code=503, detail="Bootstrap token is not configured on this instance.")
        if payload.bootstrap_token.strip() != self._settings.bootstrap_token:
            raise HTTPException(status_code=403, detail="Invalid bootstrap token.")

        approver = self._ensure_approver(
            ApproverIdentityIn(email=payload.email.lower(), display_name=payload.display_name),
            require_existing=False,
        )
        existing = self._db.fetchall(
            "SELECT credential_id FROM webauthn_credentials WHERE approver_id = ?",
            (approver["id"],),
        )
        options, challenge = self._webauthn.generate_registration(
            user_id=approver["id"],
            user_name=approver["email"],
            user_display_name=approver.get("display_name") or approver["email"],
            exclude_credential_ids=[row["credential_id"] for row in existing],
            is_ledger=False,
        )
        session_id = stable_id("bootstrap")
        self._db.execute(
            """
            INSERT INTO bootstrap_sessions(id, approver_id, email, display_name, challenge, options_json, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                approver["id"],
                approver["email"],
                approver.get("display_name"),
                challenge,
                json_dumps(options),
                add_minutes_iso(self._settings.challenge_ttl_minutes),
                utc_now_iso(),
            ),
        )
        self._audit.log(
            event_type="bootstrap.started",
            resource_type="instance",
            resource_id=self._settings.instance_id,
            actor=approver["id"],
            payload={"session_id": session_id, "email": approver["email"]},
        )
        return BootstrapStartResponse(session_id=session_id, public_key_options=options)

    def complete_bootstrap(self, payload: BootstrapCompleteRequest) -> tuple[AdminSessionResponse, str, str]:
        if self.is_initialized():
            raise HTTPException(status_code=400, detail="ClawPass is already initialized.")
        session = self._db.fetchone("SELECT * FROM bootstrap_sessions WHERE id = ?", (payload.session_id,))
        if not session:
            raise HTTPException(status_code=404, detail="Bootstrap session not found.")
        if parse_iso(session["expires_at"]) <= utc_now():
            raise HTTPException(status_code=400, detail="Bootstrap session expired. Start again.")

        verification = self._webauthn.verify_registration(
            credential=payload.credential,
            challenge=session["challenge"],
        )
        now = utc_now_iso()
        credential_row_id = stable_id("cred")
        approver = self._db.fetchone("SELECT * FROM approvers WHERE id = ?", (session["approver_id"],))
        if not approver:
            self._db.execute(
                "INSERT INTO approvers(id, email, display_name, created_at) VALUES (?, ?, ?, ?)",
                (session["approver_id"], session["email"].lower(), session.get("display_name"), now),
            )
        self._db.execute(
            """
            INSERT INTO webauthn_credentials(
              id, approver_id, credential_id, public_key, sign_count, transports_json, aaguid, label, created_at, is_ledger
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(credential_id) DO UPDATE SET
              approver_id=excluded.approver_id,
              public_key=excluded.public_key,
              sign_count=excluded.sign_count,
              transports_json=excluded.transports_json,
              aaguid=excluded.aaguid,
              label=excluded.label,
              is_ledger=excluded.is_ledger
            """,
            (
                credential_row_id,
                session["approver_id"],
                verification.credential_id,
                verification.credential_public_key,
                verification.sign_count,
                "[]",
                verification.aaguid,
                payload.label or "Primary passkey",
                now,
                0,
            ),
        )
        admin_id = stable_id("admin")
        self._db.execute(
            """
            INSERT INTO admins(id, approver_id, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(approver_id) DO NOTHING
            """,
            (admin_id, session["approver_id"], now),
        )
        admin = self._db.fetchone("SELECT * FROM admins WHERE approver_id = ?", (session["approver_id"],))
        self._db.execute("DELETE FROM bootstrap_sessions WHERE id = ?", (payload.session_id,))
        self._audit.log(
            event_type="bootstrap.completed",
            resource_type="instance",
            resource_id=self._settings.instance_id,
            actor=session["approver_id"],
            payload={"admin_id": admin["id"], "approver_id": session["approver_id"]},
        )
        session_id, csrf_token = self._issue_session_for_approver(session["approver_id"])
        response = self.get_session_response(session["approver_id"])
        return response, session_id, csrf_token

    def start_login(self, payload: LoginStartRequest) -> AdminLoginStartResponse:
        approver = self._ensure_approver(
            ApproverIdentityIn(email=payload.email.lower()),
            require_existing=True,
        )
        return self._start_login_for_approver(approver["id"])

    def start_admin_login(self) -> AdminLoginStartResponse:
        admin = self._require_single_admin()
        return self._start_login_for_approver(admin["approver_id"])

    def complete_login(self, payload: AdminLoginCompleteRequest) -> tuple[AdminSessionResponse, str, str]:
        session = self._db.fetchone("SELECT * FROM approver_login_sessions WHERE id = ?", (payload.session_id,))
        if not session:
            session = self._db.fetchone("SELECT * FROM admin_login_sessions WHERE id = ?", (payload.session_id,))
            if session and session.get("admin_id"):
                admin = self._require_admin(session["admin_id"])
                approver_id = admin["approver_id"]
            else:
                approver_id = None
        else:
            approver_id = session["approver_id"]
        if not session or not approver_id:
            raise HTTPException(status_code=404, detail="Login session not found.")
        if parse_iso(session["expires_at"]) <= utc_now():
            raise HTTPException(status_code=400, detail="Login session expired.")

        self._verify_authentication_proof(approver_id, session["challenge"], payload.credential)
        self._db.execute("DELETE FROM approver_login_sessions WHERE id = ?", (payload.session_id,))
        self._db.execute("DELETE FROM admin_login_sessions WHERE id = ?", (payload.session_id,))
        session_id, csrf_token = self._issue_session_for_approver(approver_id)
        return self.get_session_response(approver_id), session_id, csrf_token

    def complete_admin_login(self, payload: AdminLoginCompleteRequest) -> tuple[AdminSessionResponse, str, str]:
        return self.complete_login(payload)

    def resolve_human_session(
        self,
        session_id: str | None,
        *,
        csrf_token: str | None = None,
        require_csrf: bool = False,
    ) -> AdminSessionPrincipal | None:
        if not session_id:
            return None

        admin_session = self._db.fetchone("SELECT * FROM admin_sessions WHERE id = ?", (session_id,))
        if admin_session:
            if parse_iso(admin_session["expires_at"]) <= utc_now():
                self._db.execute("DELETE FROM admin_sessions WHERE id = ?", (session_id,))
                return None
            if require_csrf and csrf_token != admin_session["csrf_token"]:
                raise HTTPException(status_code=403, detail="Invalid CSRF token.")
            admin = self._require_admin(admin_session["admin_id"])
            self._db.execute("UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?", (utc_now_iso(), session_id))
            return AdminSessionPrincipal(
                admin_id=admin["id"],
                approver_id=admin["approver_id"],
                email=admin["email"],
                display_name=admin.get("display_name"),
                session_id=session_id,
                csrf_token=admin_session["csrf_token"],
            )

        approver_session = self._db.fetchone("SELECT * FROM approver_sessions WHERE id = ?", (session_id,))
        if not approver_session:
            return None
        if parse_iso(approver_session["expires_at"]) <= utc_now():
            self._db.execute("DELETE FROM approver_sessions WHERE id = ?", (session_id,))
            return None
        if require_csrf and csrf_token != approver_session["csrf_token"]:
            raise HTTPException(status_code=403, detail="Invalid CSRF token.")
        approver = self._db.fetchone("SELECT * FROM approvers WHERE id = ?", (approver_session["approver_id"],))
        if not approver:
            self._db.execute("DELETE FROM approver_sessions WHERE id = ?", (session_id,))
            return None
        admin = self._get_admin_by_approver_id(approver["id"])
        self._db.execute("UPDATE approver_sessions SET last_seen_at = ? WHERE id = ?", (utc_now_iso(), session_id))
        return AdminSessionPrincipal(
            admin_id=admin["id"] if admin else None,
            approver_id=approver["id"],
            email=approver["email"],
            display_name=approver.get("display_name"),
            session_id=session_id,
            csrf_token=approver_session["csrf_token"],
        )

    def resolve_admin_session(
        self,
        session_id: str | None,
        *,
        csrf_token: str | None = None,
        require_csrf: bool = False,
    ) -> AdminSessionPrincipal | None:
        principal = self.resolve_human_session(session_id, csrf_token=csrf_token, require_csrf=require_csrf)
        if not principal or not principal.is_admin:
            return None
        return principal

    def require_human_session(
        self,
        session_id: str | None,
        *,
        csrf_token: str | None = None,
        require_csrf: bool = False,
    ) -> AdminSessionPrincipal:
        principal = self.resolve_human_session(session_id, csrf_token=csrf_token, require_csrf=require_csrf)
        if not principal:
            raise HTTPException(status_code=401, detail="Approver authentication required.")
        return principal

    def require_admin_session(
        self,
        session_id: str | None,
        *,
        csrf_token: str | None = None,
        require_csrf: bool = False,
    ) -> AdminSessionPrincipal:
        principal = self.require_human_session(session_id, csrf_token=csrf_token, require_csrf=require_csrf)
        if not principal.is_admin:
            raise HTTPException(status_code=403, detail="Admin authentication required.")
        return principal

    def logout_session(self, session_id: str | None) -> None:
        if session_id:
            self._db.execute("DELETE FROM admin_sessions WHERE id = ?", (session_id,))
            self._db.execute("DELETE FROM approver_sessions WHERE id = ?", (session_id,))

    def logout_admin_session(self, session_id: str | None) -> None:
        self.logout_session(session_id)

    def get_session_response(self, approver_id: str) -> AdminSessionResponse:
        approver = self._db.fetchone("SELECT * FROM approvers WHERE id = ?", (approver_id,))
        if not approver:
            raise HTTPException(status_code=404, detail="Approver not found.")
        admin = self._get_admin_by_approver_id(approver_id)
        summary = self.get_approver_summary(approver_id)
        return AdminSessionResponse(
            admin_id=admin["id"] if admin else None,
            approver_id=summary.id,
            email=summary.email,
            display_name=summary.display_name,
            passkey_count=summary.passkey_count,
            ledger_webauthn_count=summary.ledger_webauthn_count,
            ethereum_signer_count=summary.ethereum_signer_count,
            is_admin=bool(admin),
        )

    def get_admin_session_response(self, admin_id: str) -> AdminSessionResponse:
        admin = self._require_admin(admin_id)
        return self.get_session_response(admin["approver_id"])

    def list_producers(self) -> list[ProducerResponse]:
        rows = self._db.fetchall("SELECT * FROM producers ORDER BY created_at DESC, id DESC")
        return [
            ProducerResponse(
                id=row["id"],
                name=row["name"],
                description=row.get("description"),
                created_at=row["created_at"],
                revoked_at=row.get("revoked_at"),
            )
            for row in rows
        ]

    def list_approvers(self) -> list[ApproverResponse]:
        rows = self._db.fetchall("SELECT * FROM approvers ORDER BY created_at DESC, id DESC")
        approvers: list[ApproverResponse] = []
        for row in rows:
            summary = self.get_approver_summary(row["id"])
            approvers.append(
                ApproverResponse(
                    id=row["id"],
                    email=row["email"],
                    display_name=row.get("display_name"),
                    created_at=row["created_at"],
                    passkey_count=summary.passkey_count,
                    ledger_webauthn_count=summary.ledger_webauthn_count,
                    ethereum_signer_count=summary.ethereum_signer_count,
                )
            )
        return approvers

    def list_approver_invites(self) -> list[ApproverInviteResponse]:
        rows = self._db.fetchall("SELECT * FROM approver_invites ORDER BY created_at DESC, token DESC")
        return [self._to_approver_invite_response(row) for row in rows]

    def create_approver_invite(self, payload: ApproverInviteCreateRequest) -> ApproverInviteResponse:
        approver = self._ensure_approver(
            ApproverIdentityIn(email=payload.email.lower(), display_name=payload.display_name),
            require_existing=False,
        )
        token = token_urlsafe(24)
        created_at = utc_now_iso()
        expires_at = add_minutes_iso(payload.expires_in_minutes or (24 * 60))
        self._db.execute(
            """
            INSERT INTO approver_invites(token, approver_id, email, display_name, next_path, expires_at, created_at, consumed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                token,
                approver["id"],
                approver["email"],
                approver.get("display_name"),
                payload.next_path,
                expires_at,
                created_at,
            ),
        )
        row = self._db.fetchone("SELECT * FROM approver_invites WHERE token = ?", (token,))
        self._audit.log(
            event_type="approver.invite.created",
            resource_type="approver",
            resource_id=approver["id"],
            actor="system",
            payload={"token": token, "email": approver["email"], "expires_at": expires_at},
        )
        return self._to_approver_invite_response(row)

    def get_approver_invite(self, token: str) -> ApproverInviteResponse:
        return self._to_approver_invite_response(self._require_invite(token))

    def start_approver_invite_enrollment(self, token: str) -> WebAuthnRegisterStartResponse:
        invite = self._require_invite(token)
        return self.start_webauthn_registration(
            WebAuthnRegisterStartRequest(
                approver_id=invite["approver_id"],
                is_ledger=False,
                label="Primary passkey",
            )
        )

    def complete_approver_invite_enrollment(
        self,
        token: str,
        payload: WebAuthnRegisterCompleteRequest,
    ) -> tuple[AdminSessionResponse, str, str]:
        invite = self._require_invite(token)
        completed = self.complete_webauthn_registration(payload)
        if completed.approver_id != invite["approver_id"]:
            raise HTTPException(status_code=400, detail="Invite enrollment does not match the invited approver.")
        consumed_at = utc_now_iso()
        self._db.execute("UPDATE approver_invites SET consumed_at = ? WHERE token = ?", (consumed_at, token))
        session_id, csrf_token = self._issue_session_for_approver(invite["approver_id"])
        self._audit.log(
            event_type="approver.invite.accepted",
            resource_type="approver",
            resource_id=invite["approver_id"],
            actor=invite["approver_id"],
            payload={"token": token},
        )
        return self.get_session_response(invite["approver_id"]), session_id, csrf_token

    def create_producer(self, payload: ProducerCreateRequest) -> ProducerResponse:
        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Producer name is required.")
        producer_id = stable_id("producer")
        now = utc_now_iso()
        try:
            self._db.execute(
                "INSERT INTO producers(id, name, description, created_at, revoked_at) VALUES (?, ?, ?, ?, NULL)",
                (producer_id, name, payload.description, now),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail=f"Producer '{payload.name}' already exists.") from exc
        return ProducerResponse(
            id=producer_id,
            name=name,
            description=payload.description,
            created_at=now,
            revoked_at=None,
        )

    def issue_producer_key(self, producer_id: str, payload: ProducerKeyCreateRequest) -> ProducerKeyResponse:
        producer = self._require_producer(producer_id)
        if producer.get("revoked_at"):
            raise HTTPException(status_code=400, detail="Producer is revoked.")
        key_id = stable_id("pkey")
        secret = token_urlsafe(24)
        created_at = utc_now_iso()
        self._db.execute(
            """
            INSERT INTO producer_api_keys(id, producer_id, public_key_id, secret_hash, label, created_at, last_used_at, revoked_at)
            VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
            """,
            (key_id, producer_id, key_id, hash_secret(secret), payload.label, created_at),
        )
        return ProducerKeyResponse(
            key_id=key_id,
            producer_id=producer_id,
            api_key=make_api_key(key_id, secret),
            created_at=created_at,
            label=payload.label,
        )

    def revoke_producer_key(self, producer_id: str, key_id: str) -> ProducerKeyResponse:
        row = self._db.fetchone(
            "SELECT * FROM producer_api_keys WHERE public_key_id = ? AND producer_id = ?",
            (key_id, producer_id),
        )
        if not row:
            raise HTTPException(status_code=404, detail="Producer key not found.")
        revoked_at = utc_now_iso()
        self._db.execute(
            "UPDATE producer_api_keys SET revoked_at = ? WHERE public_key_id = ? AND producer_id = ?",
            (revoked_at, key_id, producer_id),
        )
        return ProducerKeyResponse(
            key_id=key_id,
            producer_id=producer_id,
            api_key=None,
            created_at=row["created_at"],
            label=row.get("label"),
        )

    def resolve_producer(self, authorization_header: str | None) -> ProducerPrincipal | None:
        token = extract_bearer_token(authorization_header)
        if not token:
            return None
        parsed = split_api_key(token)
        if not parsed:
            return None
        public_key_id, secret = parsed
        row = self._db.fetchone(
            """
            SELECT p.id AS producer_id, p.name, p.revoked_at AS producer_revoked_at,
                   k.public_key_id, k.secret_hash, k.revoked_at AS key_revoked_at
            FROM producer_api_keys k
            JOIN producers p ON p.id = k.producer_id
            WHERE k.public_key_id = ?
            """,
            (public_key_id,),
        )
        if not row or row.get("key_revoked_at") or row.get("producer_revoked_at"):
            return None
        if not secret_matches(secret, row["secret_hash"]):
            return None
        self._db.execute(
            "UPDATE producer_api_keys SET last_used_at = ? WHERE public_key_id = ?",
            (utc_now_iso(), public_key_id),
        )
        return ProducerPrincipal(
            producer_id=row["producer_id"],
            key_id=public_key_id,
            name=row["name"],
        )

    def require_producer(self, authorization_header: str | None) -> ProducerPrincipal:
        principal = self.resolve_producer(authorization_header)
        if not principal:
            raise HTTPException(status_code=401, detail="Producer API key required.")
        return principal

    def start_webauthn_registration(self, payload: WebAuthnRegisterStartRequest) -> WebAuthnRegisterStartResponse:
        approver = self._ensure_approver(payload)
        existing = self._db.fetchall(
            "SELECT credential_id FROM webauthn_credentials WHERE approver_id = ?",
            (approver["id"],),
        )
        options, challenge = self._webauthn.generate_registration(
            user_id=approver["id"],
            user_name=approver["email"],
            user_display_name=approver.get("display_name") or approver["email"],
            exclude_credential_ids=[row["credential_id"] for row in existing],
            is_ledger=payload.is_ledger,
        )
        session_id = stable_id("webauthn_reg")
        self._db.execute(
            """
            INSERT INTO webauthn_registration_sessions(id, approver_id, challenge, options_json, expires_at, created_at, is_ledger)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                approver["id"],
                challenge,
                json_dumps(options),
                add_minutes_iso(self._settings.challenge_ttl_minutes),
                utc_now_iso(),
                1 if payload.is_ledger else 0,
            ),
        )
        self._audit.log(
            event_type="webauthn.registration.started",
            resource_type="approver",
            resource_id=approver["id"],
            actor=approver["id"],
            payload={"session_id": session_id, "is_ledger": payload.is_ledger},
        )
        return WebAuthnRegisterStartResponse(session_id=session_id, approver_id=approver["id"], public_key_options=options)

    def complete_webauthn_registration(self, payload: WebAuthnRegisterCompleteRequest) -> WebAuthnRegisterCompleteResponse:
        session = self._db.fetchone(
            "SELECT * FROM webauthn_registration_sessions WHERE id = ?",
            (payload.session_id,),
        )
        if not session:
            raise HTTPException(status_code=404, detail="Registration session not found.")
        if parse_iso(session["expires_at"]) <= utc_now():
            raise HTTPException(status_code=400, detail="Registration session expired. Start again.")

        verification = self._webauthn.verify_registration(
            credential=payload.credential,
            challenge=session["challenge"],
        )
        now = utc_now_iso()
        credential_row_id = stable_id("cred")
        self._db.execute(
            """
            INSERT INTO webauthn_credentials(
              id, approver_id, credential_id, public_key, sign_count, transports_json, aaguid, label, created_at, is_ledger
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(credential_id) DO UPDATE SET
              approver_id=excluded.approver_id,
              public_key=excluded.public_key,
              sign_count=excluded.sign_count,
              transports_json=excluded.transports_json,
              aaguid=excluded.aaguid,
              label=excluded.label,
              is_ledger=excluded.is_ledger
            """,
            (
                credential_row_id,
                session["approver_id"],
                verification.credential_id,
                verification.credential_public_key,
                verification.sign_count,
                "[]",
                verification.aaguid,
                payload.label,
                now,
                int(session["is_ledger"]),
            ),
        )
        self._db.execute("DELETE FROM webauthn_registration_sessions WHERE id = ?", (payload.session_id,))
        self._audit.log(
            event_type="webauthn.registration.completed",
            resource_type="approver",
            resource_id=session["approver_id"],
            actor=session["approver_id"],
            payload={"credential_id": verification.credential_id, "is_ledger": bool(session["is_ledger"] )},
        )
        return WebAuthnRegisterCompleteResponse(
            approver_id=session["approver_id"],
            credential_id=verification.credential_id,
            is_ledger=bool(session["is_ledger"]),
        )

    def create_approval_request(
        self,
        payload: CreateApprovalRequest,
        *,
        producer_id: str | None = None,
    ) -> ApprovalRequestResponse:
        request_id = payload.request_id or stable_id("apr")
        risk_level = payload.risk_level.lower()
        if risk_level not in VALID_RISK_LEVELS:
            raise HTTPException(status_code=400, detail=f"Unsupported risk_level '{payload.risk_level}'.")

        expires_at = payload.expires_at or add_minutes_iso(self._settings.approval_default_ttl_minutes)
        try:
            parsed_expires_at = parse_iso(expires_at)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="expires_at must be a valid ISO 8601 timestamp.") from exc
        parsed_expires_at = parsed_expires_at.astimezone(timezone.utc)
        expires_at = parsed_expires_at.isoformat().replace("+00:00", "Z")
        if parsed_expires_at <= utc_now():
            raise HTTPException(status_code=400, detail="expires_at must be in the future.")

        now = utc_now_iso()
        nonce = token_urlsafe(12)
        try:
            self._db.execute(
                """
                INSERT INTO approval_requests(
                  id, producer_id, action_type, action_ref, action_hash, requester_id, risk_level, metadata_json, status,
                  decision, approver_id, method, created_at, expires_at, decided_at, nonce, callback_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, NULL, ?, ?)
                """,
                (
                    request_id,
                    producer_id,
                    payload.action_type,
                    payload.action_ref,
                    payload.action_hash,
                    payload.requester_id,
                    risk_level,
                    json_dumps(payload.metadata),
                    APPROVAL_STATUS_PENDING,
                    now,
                    expires_at,
                    nonce,
                    payload.callback_url,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail=f"Approval request '{request_id}' already exists.") from exc

        row = self._require_request(request_id)
        self._emit_request_event(row, EVENT_APPROVAL_PENDING)
        self._audit.log(
            event_type="approval.request.created",
            resource_type="approval_request",
            resource_id=request_id,
            actor=producer_id or payload.requester_id,
            payload={"risk_level": risk_level, "action_type": payload.action_type, "producer_id": producer_id},
        )
        return self._to_approval_response(row)

    def get_approval_link(self, request_id: str) -> ApprovalLinkResponse:
        row = self._expire_if_needed(self._require_request(request_id))
        return ApprovalLinkResponse(
            id=row["id"],
            producer_id=row.get("producer_id"),
            action_type=row["action_type"],
            action_ref=row.get("action_ref"),
            risk_level=row["risk_level"],
            status=row["status"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            approval_url=self._approval_url(row["id"]),
        )

    def get_approval_request(self, request_id: str, *, producer_id: str | None = None) -> ApprovalRequestResponse:
        row = self._require_request(request_id)
        if producer_id and row.get("producer_id") != producer_id:
            raise HTTPException(status_code=404, detail="Approval request not found.")
        row = self._expire_if_needed(row)
        return self._to_approval_response(row)

    def cancel_approval_request(
        self,
        request_id: str,
        *,
        reason: str | None,
        actor: str = "system",
        producer_id: str | None = None,
    ) -> ApprovalRequestResponse:
        row = self._require_request(request_id)
        if producer_id and row.get("producer_id") != producer_id:
            raise HTTPException(status_code=404, detail="Approval request not found.")
        row = self._expire_if_needed(row)
        if row["status"] != APPROVAL_STATUS_PENDING:
            raise HTTPException(status_code=400, detail="Only pending requests can be cancelled.")
        now = utc_now_iso()
        self._db.execute(
            """
            UPDATE approval_requests
            SET status = ?, decision = ?, decided_at = ?, method = ?, approver_id = ?
            WHERE id = ?
            """,
            (
                APPROVAL_STATUS_CANCELLED,
                "CANCELLED",
                now,
                "system",
                None,
                request_id,
            ),
        )
        self._audit.log(
            event_type="approval.request.cancelled",
            resource_type="approval_request",
            resource_id=request_id,
            actor=actor,
            payload={"reason": reason, "producer_id": row.get("producer_id")},
        )
        updated = self._require_request(request_id)
        self._emit_request_event(updated, EVENT_APPROVAL_CANCELLED)
        return self._to_approval_response(updated)

    def start_decision(self, request_id: str, payload: DecisionStartRequest) -> DecisionStartResponse:
        request_row = self._expire_if_needed(self._require_request(request_id))
        if request_row["status"] != APPROVAL_STATUS_PENDING:
            raise HTTPException(status_code=400, detail="Approval request is not pending.")

        approver = self._ensure_approver(ApproverIdentityIn(approver_id=payload.approver_id), require_existing=True)
        passkey_count = self._count_passkeys(approver["id"])
        policy = self._policy.can_start_decision(risk_level=request_row["risk_level"], passkey_count=passkey_count)
        if not policy.allowed:
            raise HTTPException(status_code=400, detail=policy.reason or "Policy rejected decision start.")

        challenge_id = stable_id("decch")
        expires_at = add_minutes_iso(self._settings.challenge_ttl_minutes)
        challenge = token_urlsafe(20)
        payload_data: dict[str, Any] = {}

        if payload.method in {METHOD_WEBAUTHN, METHOD_LEDGER_WEBAUTHN}:
            credential_rows = self._db.fetchall(
                """
                SELECT credential_id, is_ledger
                FROM webauthn_credentials
                WHERE approver_id = ? AND is_ledger = ?
                """,
                (approver["id"], 1 if payload.method == METHOD_LEDGER_WEBAUTHN else 0),
            )
            if not credential_rows:
                raise HTTPException(status_code=400, detail="No matching WebAuthn credentials enrolled for this method.")
            public_key_options, challenge = self._webauthn.generate_authentication(
                allowed_credential_ids=[row["credential_id"] for row in credential_rows]
            )
            payload_data = {
                "public_key_options": public_key_options,
                "decision_envelope": {
                    "request_id": request_row["id"],
                    "decision": payload.decision,
                    "action_hash": request_row["action_hash"],
                    "nonce": request_row["nonce"],
                    "expires_at": request_row["expires_at"],
                },
            }
        elif payload.method == METHOD_ETHEREUM_SIGNER:
            signer_rows = self._db.fetchall(
                "SELECT address, chain_id FROM ethereum_signers WHERE approver_id = ?",
                (approver["id"],),
            )
            if not signer_rows:
                raise HTTPException(status_code=400, detail="No Ethereum signer enrolled for this approver.")
            chain_id = int(signer_rows[0]["chain_id"] or 1)
            eth_challenge = self._ethereum.build_approval_decision_challenge(
                request_id=request_row["id"],
                decision=payload.decision,
                action_hash=request_row["action_hash"],
                chain_id=chain_id,
                nonce=request_row["nonce"],
                expires_at=request_row["expires_at"],
            )
            challenge = eth_challenge.digest
            payload_data = {
                "typed_data": eth_challenge.typed_data,
                "allowed_addresses": [row["address"].lower() for row in signer_rows],
                "decision_envelope": {
                    "request_id": request_row["id"],
                    "decision": payload.decision,
                    "action_hash": request_row["action_hash"],
                    "nonce": request_row["nonce"],
                    "expires_at": request_row["expires_at"],
                },
            }
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported method '{payload.method}'.")

        self._db.execute(
            """
            INSERT INTO decision_challenges(id, request_id, approver_id, method, decision, challenge, payload_json, expires_at, created_at, consumed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                challenge_id,
                request_row["id"],
                approver["id"],
                payload.method,
                payload.decision,
                challenge,
                json_dumps(payload_data),
                expires_at,
                utc_now_iso(),
            ),
        )

        self._audit.log(
            event_type="approval.decision.started",
            resource_type="approval_request",
            resource_id=request_row["id"],
            actor=approver["id"],
            payload={"method": payload.method, "decision": payload.decision, "challenge_id": challenge_id},
        )

        return DecisionStartResponse(
            challenge_id=challenge_id,
            method=payload.method,
            expires_at=expires_at,
            payload=payload_data,
        )

    def complete_decision(self, request_id: str, payload: DecisionCompleteRequest) -> ApprovalRequestResponse:
        challenge_row = self._db.fetchone("SELECT * FROM decision_challenges WHERE id = ?", (payload.challenge_id,))
        if not challenge_row or challenge_row["request_id"] != request_id:
            raise HTTPException(status_code=404, detail="Decision challenge not found for request.")
        if challenge_row["consumed_at"]:
            raise HTTPException(status_code=400, detail="Decision challenge already used.")
        if parse_iso(challenge_row["expires_at"]) <= utc_now():
            raise HTTPException(status_code=400, detail="Decision challenge expired.")

        request_row = self._expire_if_needed(self._require_request(request_id))
        if request_row["status"] != APPROVAL_STATUS_PENDING:
            raise HTTPException(status_code=400, detail="Approval request is no longer pending.")

        challenge_payload = json.loads(challenge_row["payload_json"])
        method = challenge_row["method"]
        approver_id = challenge_row["approver_id"]

        envelope = challenge_payload.get("decision_envelope") or {}
        if (
            envelope.get("request_id") != request_row["id"]
            or envelope.get("action_hash") != request_row["action_hash"]
            or envelope.get("nonce") != request_row["nonce"]
        ):
            raise HTTPException(
                status_code=400,
                detail="Decision envelope does not match current approval request hash/nonce binding.",
            )

        if method in {METHOD_WEBAUTHN, METHOD_LEDGER_WEBAUTHN}:
            credential = payload.proof.get("credential")
            if not isinstance(credential, dict):
                raise HTTPException(status_code=400, detail="WebAuthn proof must include a credential object.")
            credential_id = str(credential.get("id") or credential.get("rawId") or "").strip()
            if not credential_id:
                raise HTTPException(status_code=400, detail="WebAuthn credential id missing in proof.")
            is_ledger = 1 if method == METHOD_LEDGER_WEBAUTHN else 0
            credential_row = self._db.fetchone(
                """
                SELECT * FROM webauthn_credentials
                WHERE approver_id = ? AND credential_id = ? AND is_ledger = ?
                """,
                (approver_id, credential_id, is_ledger),
            )
            if not credential_row:
                raise HTTPException(status_code=400, detail="Credential not enrolled for approver and method.")

            try:
                new_sign_count = self._webauthn.verify_authentication(
                    credential=credential,
                    challenge=challenge_row["challenge"],
                    credential_public_key=credential_row["public_key"],
                    credential_current_sign_count=int(credential_row["sign_count"]),
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            self._db.execute(
                """
                UPDATE webauthn_credentials
                SET sign_count = ?, last_used_at = ?
                WHERE id = ?
                """,
                (new_sign_count, utc_now_iso(), credential_row["id"]),
            )
        elif method == METHOD_ETHEREUM_SIGNER:
            signature = str(payload.proof.get("signature") or "").strip()
            if not signature:
                raise HTTPException(status_code=400, detail="Ethereum proof must include signature.")
            try:
                recovered = self._ethereum.verify_signature(
                    typed_data=challenge_payload["typed_data"],
                    signature=signature,
                )
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Ethereum signature verification failed: {exc}") from exc

            allowed_addresses = {value.lower() for value in challenge_payload.get("allowed_addresses", [])}
            if recovered.lower() not in allowed_addresses:
                raise HTTPException(status_code=400, detail="Recovered signer is not authorized for this approver.")

            signer_row = self._db.fetchone(
                "SELECT id FROM ethereum_signers WHERE approver_id = ? AND LOWER(address) = ?",
                (approver_id, recovered.lower()),
            )
            if signer_row:
                self._db.execute(
                    "UPDATE ethereum_signers SET last_used_at = ? WHERE id = ?",
                    (utc_now_iso(), signer_row["id"]),
                )
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported challenge method '{method}'.")

        final_status = APPROVAL_STATUS_APPROVED if challenge_row["decision"] == DECISION_APPROVE else APPROVAL_STATUS_DENIED
        decision_event = EVENT_APPROVAL_APPROVED if final_status == APPROVAL_STATUS_APPROVED else EVENT_APPROVAL_DENIED
        now = utc_now_iso()

        self._db.execute_many(
            [
                (
                    """
                    UPDATE approval_requests
                    SET status = ?, decision = ?, approver_id = ?, method = ?, decided_at = ?
                    WHERE id = ?
                    """,
                    (final_status, challenge_row["decision"], approver_id, method, now, request_id),
                ),
                (
                    "UPDATE decision_challenges SET consumed_at = ? WHERE id = ?",
                    (now, payload.challenge_id),
                ),
            ]
        )

        updated = self._require_request(request_id)
        self._emit_request_event(updated, decision_event)
        self._audit.log(
            event_type="approval.decision.completed",
            resource_type="approval_request",
            resource_id=request_id,
            actor=approver_id,
            payload={"method": method, "decision": challenge_row["decision"], "status": final_status},
        )
        return self._to_approval_response(updated)

    def start_ethereum_signer_challenge(self, payload: EthereumSignerChallengeRequest) -> EthereumSignerChallengeResponse:
        approver = self._ensure_approver(payload)
        normalized_address = payload.address.lower()
        challenge = self._ethereum.build_signer_enrollment_challenge(
            approver_id=approver["id"],
            address=normalized_address,
            chain_id=payload.chain_id,
            expires_at=add_minutes_iso(self._settings.challenge_ttl_minutes),
        )
        session_id = stable_id("ethsig")
        self._db.execute(
            """
            INSERT INTO ethereum_signer_sessions(
              id, approver_id, address, challenge_json, challenge_digest, expires_at, created_at, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                session_id,
                approver["id"],
                normalized_address,
                json_dumps(challenge.typed_data),
                challenge.digest,
                challenge.typed_data["message"]["expiresAt"],
                utc_now_iso(),
            ),
        )
        self._audit.log(
            event_type="ethereum.signer.challenge.started",
            resource_type="approver",
            resource_id=approver["id"],
            actor=approver["id"],
            payload={"address": normalized_address, "session_id": session_id},
        )
        return EthereumSignerChallengeResponse(
            session_id=session_id,
            approver_id=approver["id"],
            typed_data=challenge.typed_data,
            digest=challenge.digest,
        )

    def verify_ethereum_signer(self, payload: EthereumSignerVerifyRequest) -> EthereumSignerVerifyResponse:
        session = self._db.fetchone("SELECT * FROM ethereum_signer_sessions WHERE id = ?", (payload.session_id,))
        if not session:
            raise HTTPException(status_code=404, detail="Ethereum signer session not found.")
        if session["consumed_at"]:
            raise HTTPException(status_code=400, detail="Ethereum signer session already used.")
        if parse_iso(session["expires_at"]) <= utc_now():
            raise HTTPException(status_code=400, detail="Ethereum signer session expired.")

        typed_data = json.loads(session["challenge_json"])
        try:
            recovered = self._ethereum.verify_signature(typed_data=typed_data, signature=payload.signature)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Ethereum signature verification failed: {exc}") from exc
        if recovered.lower() != session["address"].lower():
            raise HTTPException(status_code=400, detail="Signature recovered a different wallet address.")

        signer_id = stable_id("signer")
        self._db.execute_many(
            [
                (
                    """
                    INSERT INTO ethereum_signers(id, approver_id, address, chain_id, created_at, last_used_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(address) DO UPDATE SET
                      approver_id=excluded.approver_id,
                      chain_id=excluded.chain_id,
                      last_used_at=excluded.last_used_at
                    """,
                    (
                        signer_id,
                        session["approver_id"],
                        session["address"].lower(),
                        int(typed_data["domain"]["chainId"]),
                        utc_now_iso(),
                        utc_now_iso(),
                    ),
                ),
                (
                    "UPDATE ethereum_signer_sessions SET consumed_at = ? WHERE id = ?",
                    (utc_now_iso(), payload.session_id),
                ),
            ]
        )
        self._audit.log(
            event_type="ethereum.signer.verified",
            resource_type="approver",
            resource_id=session["approver_id"],
            actor=session["approver_id"],
            payload={"address": session["address"].lower()},
        )
        return EthereumSignerVerifyResponse(
            approver_id=session["approver_id"],
            address=session["address"].lower(),
            chain_id=int(typed_data["domain"]["chainId"]),
        )

    def get_approver_summary(self, approver_id: str) -> ApproverSummary:
        approver = self._db.fetchone("SELECT * FROM approvers WHERE id = ?", (approver_id,))
        if not approver:
            raise HTTPException(status_code=404, detail="Approver not found.")
        passkey_count = self._db.fetchone(
            "SELECT COUNT(*) AS count FROM webauthn_credentials WHERE approver_id = ? AND is_ledger = 0",
            (approver_id,),
        )["count"]
        ledger_webauthn_count = self._db.fetchone(
            "SELECT COUNT(*) AS count FROM webauthn_credentials WHERE approver_id = ? AND is_ledger = 1",
            (approver_id,),
        )["count"]
        ethereum_signer_count = self._db.fetchone(
            "SELECT COUNT(*) AS count FROM ethereum_signers WHERE approver_id = ?",
            (approver_id,),
        )["count"]
        return ApproverSummary(
            id=approver["id"],
            email=approver["email"],
            display_name=approver.get("display_name"),
            passkey_count=int(passkey_count),
            ledger_webauthn_count=int(ledger_webauthn_count),
            ethereum_signer_count=int(ethereum_signer_count),
        )

    def list_webhook_events(
        self,
        request_id: str | None = None,
        *,
        status: str | None = None,
        event_type: str | None = None,
        callback_url: str | None = None,
        limit: int = 200,
        cursor: str | None = None,
    ) -> list[WebhookEventResponse]:
        if limit < 1 or limit > 200:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 200.")
        clauses: list[str] = []
        params: list[str] = []

        if request_id:
            clauses.append("request_id = ?")
            params.append(request_id)

        if status:
            normalized_status = status.lower()
            if normalized_status not in VALID_WEBHOOK_EVENT_STATUSES:
                raise HTTPException(status_code=400, detail=f"Unsupported webhook status '{status}'.")
            clauses.append("status = ?")
            params.append(normalized_status)

        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)

        if callback_url:
            clauses.append("callback_url = ?")
            params.append(callback_url)

        if cursor:
            cursor_row = self._require_webhook_event(cursor)
            clauses.append("(created_at < ? OR (created_at = ? AND id < ?))")
            params.extend([cursor_row["created_at"], cursor_row["created_at"], cursor_row["id"]])

        query = "SELECT * FROM webhook_events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        rows = self._db.fetchall(query, tuple(params + [str(limit)]))
        return [WebhookEventResponse(**row) for row in rows]

    def get_webhook_delivery_summary(self) -> WebhookDeliverySummary:
        now = utc_now()
        counts = {
            row["status"]: int(row["count"])
            for row in self._db.fetchall("SELECT status, COUNT(*) AS count FROM webhook_events GROUP BY status")
        }
        queued_rows = self._db.fetchall(
            "SELECT created_at, lease_expires_at, available_at, retry_parent_id FROM webhook_events WHERE status = ?",
            (WEBHOOK_STATUS_QUEUED,),
        )
        backlog_count = 0
        leased_backlog_count = 0
        stalled_backlog_count = 0
        scheduled_retry_count = 0
        oldest_queued_at: str | None = None
        oldest_stalled_at: str | None = None
        for row in queued_rows:
            created_at = row["created_at"]
            if oldest_queued_at is None or created_at < oldest_queued_at:
                oldest_queued_at = created_at
            available_at = row.get("available_at")
            if available_at and parse_iso(available_at) > now:
                if row.get("retry_parent_id"):
                    scheduled_retry_count += 1
                continue
            backlog_count += 1
            lease_expires_at = row.get("lease_expires_at")
            if lease_expires_at and parse_iso(lease_expires_at) > now:
                leased_backlog_count += 1
                continue
            stalled_backlog_count += 1
            if oldest_stalled_at is None or created_at < oldest_stalled_at:
                oldest_stalled_at = created_at

        delivered_count = counts.get(WEBHOOK_STATUS_DELIVERED, 0)
        failed_count = counts.get(WEBHOOK_STATUS_FAILED, 0)
        skipped_count = counts.get(WEBHOOK_STATUS_SKIPPED, 0)
        dead_lettered_count = int(
            self._db.fetchone("SELECT COUNT(*) AS count FROM webhook_events WHERE dead_lettered_at IS NOT NULL")["count"]
        )
        attempted_count = delivered_count + failed_count
        failure_rate = failed_count / attempted_count if attempted_count else 0.0

        redelivery_counts = {
            WEBHOOK_STATUS_QUEUED: 0,
            WEBHOOK_STATUS_DELIVERED: 0,
            WEBHOOK_STATUS_FAILED: 0,
        }
        redelivery_count = 0
        retry_rows = self._db.fetchall(
            "SELECT status, available_at FROM webhook_events WHERE retry_parent_id IS NOT NULL ORDER BY created_at DESC"
        )
        for row in retry_rows:
            redelivery_count += 1
            status = row["status"]
            if status in redelivery_counts:
                if status == WEBHOOK_STATUS_QUEUED and row.get("available_at") and parse_iso(row["available_at"]) > now:
                    continue
                redelivery_counts[status] += 1

        last_event_at = self._db.fetchone("SELECT MAX(created_at) AS value FROM webhook_events")["value"]
        alerts: list[str] = []
        if stalled_backlog_count >= self._settings.webhook_backlog_alert_threshold and oldest_stalled_at:
            alert_after = timedelta(seconds=self._settings.webhook_backlog_alert_after_seconds)
            if now - parse_iso(oldest_stalled_at) >= alert_after:
                alerts.append(
                    f"Webhook backlog has {stalled_backlog_count} stalled event(s) older than "
                    f"{self._settings.webhook_backlog_alert_after_seconds}s."
                )
        if attempted_count > 0 and failure_rate >= self._settings.webhook_failure_rate_alert_threshold:
            alerts.append(
                f"Webhook failure rate is {failure_rate:.0%}, above the "
                f"{self._settings.webhook_failure_rate_alert_threshold:.0%} threshold."
            )
        if dead_lettered_count > 0:
            alerts.append(f"{dead_lettered_count} webhook event(s) are dead-lettered and need operator review.")
        if redelivery_counts[WEBHOOK_STATUS_QUEUED] > 0:
            alerts.append(f"{redelivery_counts[WEBHOOK_STATUS_QUEUED]} redelivered webhook event(s) are still queued.")
        if redelivery_counts[WEBHOOK_STATUS_FAILED] > 0:
            alerts.append(f"{redelivery_counts[WEBHOOK_STATUS_FAILED]} redelivered webhook event(s) failed again.")
        muted_endpoint_count = int(
            self._db.fetchone(
                """
                SELECT COUNT(*) AS count
                FROM webhook_endpoint_controls
                WHERE muted_until IS NOT NULL AND muted_until > ?
                """,
                (utc_now_iso(),),
            )["count"]
        )
        if muted_endpoint_count > 0:
            alerts.append(f"{muted_endpoint_count} webhook endpoint(s) are temporarily muted.")

        return WebhookDeliverySummary(
            total_events=sum(counts.values()),
            backlog_count=backlog_count,
            leased_backlog_count=leased_backlog_count,
            stalled_backlog_count=stalled_backlog_count,
            scheduled_retry_count=scheduled_retry_count,
            dead_lettered_count=dead_lettered_count,
            delivered_count=delivered_count,
            failed_count=failed_count,
            skipped_count=skipped_count,
            attempted_count=attempted_count,
            failure_rate=failure_rate,
            redelivery_count=redelivery_count,
            redelivery_backlog_count=redelivery_counts[WEBHOOK_STATUS_QUEUED],
            redelivery_delivered_count=redelivery_counts[WEBHOOK_STATUS_DELIVERED],
            redelivery_failed_count=redelivery_counts[WEBHOOK_STATUS_FAILED],
            oldest_queued_at=oldest_queued_at,
            oldest_stalled_at=oldest_stalled_at,
            last_event_at=last_event_at,
            health_state="warning" if alerts else "healthy",
            alerts=alerts,
        )

    def list_webhook_endpoint_summaries(self, *, limit: int = 20) -> list[WebhookEndpointSummary]:
        if limit < 1 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 100.")

        now = utc_now()
        controls = {
            row["callback_url"]: row
            for row in self._db.fetchall("SELECT * FROM webhook_endpoint_controls ORDER BY updated_at DESC, callback_url ASC")
        }
        rows = self._db.fetchall(
            """
            SELECT callback_url, status, available_at, lease_expires_at, dead_lettered_at, last_error, created_at, updated_at
            FROM webhook_events
            WHERE callback_url IS NOT NULL
            ORDER BY updated_at DESC, id DESC
            """
        )
        grouped: dict[str, dict[str, Any]] = {}
        for callback_url, control in controls.items():
            is_muted = bool(control.get("muted_until") and parse_iso(control["muted_until"]) > now)
            grouped[callback_url] = {
                "callback_url": callback_url,
                "muted_until": control["muted_until"] if is_muted else None,
                "mute_reason": control.get("mute_reason") if is_muted else None,
                "consecutive_failure_count": int(control.get("consecutive_failure_count") or 0),
                "total_events": 0,
                "queued_count": 0,
                "stalled_count": 0,
                "delivered_count": 0,
                "failed_count": 0,
                "dead_lettered_count": 0,
                "next_attempt_at": None,
                "last_event_at": None,
                "latest_error": None,
            }
        for row in rows:
            callback_url = row["callback_url"]
            summary = grouped.setdefault(
                callback_url,
                {
                    "callback_url": callback_url,
                    "muted_until": None,
                    "mute_reason": None,
                    "consecutive_failure_count": 0,
                    "total_events": 0,
                    "queued_count": 0,
                    "stalled_count": 0,
                    "delivered_count": 0,
                    "failed_count": 0,
                    "dead_lettered_count": 0,
                    "next_attempt_at": None,
                    "last_event_at": None,
                    "latest_error": None,
                },
            )
            summary["total_events"] += 1
            status = row["status"]
            if status == WEBHOOK_STATUS_QUEUED:
                summary["queued_count"] += 1
                available_at = row.get("available_at")
                if available_at and parse_iso(available_at) > now:
                    current_next = summary["next_attempt_at"]
                    if current_next is None or available_at < current_next:
                        summary["next_attempt_at"] = available_at
                lease_expires_at = row.get("lease_expires_at")
                if (not available_at or parse_iso(available_at) <= now) and (
                    not lease_expires_at or parse_iso(lease_expires_at) <= now
                ):
                    summary["stalled_count"] += 1
            elif status == WEBHOOK_STATUS_DELIVERED:
                summary["delivered_count"] += 1
            elif status == WEBHOOK_STATUS_FAILED:
                summary["failed_count"] += 1

            if row.get("dead_lettered_at"):
                summary["dead_lettered_count"] += 1
            if row.get("last_error") and summary["latest_error"] is None:
                summary["latest_error"] = row["last_error"]
            created_at = row["created_at"]
            if summary["last_event_at"] is None or created_at > summary["last_event_at"]:
                summary["last_event_at"] = created_at

        endpoint_summaries: list[WebhookEndpointSummary] = []
        severity_order = {"critical": 0, "warning": 1, "degraded": 2, "healthy": 3}
        for entry in grouped.values():
            attempted_count = entry["delivered_count"] + entry["failed_count"]
            failure_rate = entry["failed_count"] / attempted_count if attempted_count else 0.0
            is_muted = bool(entry.get("muted_until") and parse_iso(entry["muted_until"]) > now)
            if entry["dead_lettered_count"] > 0:
                health_state = "critical"
            elif is_muted or entry["stalled_count"] > 0 or failure_rate >= self._settings.webhook_failure_rate_alert_threshold:
                health_state = "warning"
            elif entry["queued_count"] > 0:
                health_state = "degraded"
            else:
                health_state = "healthy"
            endpoint_summaries.append(
                WebhookEndpointSummary(
                    callback_url=entry["callback_url"],
                    muted_until=entry["muted_until"] if is_muted else None,
                    mute_reason=entry["mute_reason"] if is_muted else None,
                    consecutive_failure_count=entry["consecutive_failure_count"],
                    total_events=entry["total_events"],
                    queued_count=entry["queued_count"],
                    stalled_count=entry["stalled_count"],
                    delivered_count=entry["delivered_count"],
                    failed_count=entry["failed_count"],
                    dead_lettered_count=entry["dead_lettered_count"],
                    attempted_count=attempted_count,
                    failure_rate=failure_rate,
                    next_attempt_at=entry["next_attempt_at"],
                    last_event_at=entry["last_event_at"],
                    latest_error=entry["latest_error"],
                    health_state=health_state,
                )
            )
        endpoint_summaries.sort(
            key=lambda summary: (
                severity_order.get(summary.health_state, 99),
                -(parse_iso(summary.last_event_at).timestamp()) if summary.last_event_at else float("inf"),
                summary.callback_url,
            )
        )
        return endpoint_summaries[:limit]

    def mute_webhook_endpoint(
        self,
        payload: WebhookEndpointMuteRequest,
        *,
        actor: str = "system",
    ) -> WebhookEndpointControlResponse:
        callback_url = payload.callback_url.strip()
        if not callback_url:
            raise HTTPException(status_code=400, detail="callback_url is required.")
        muted_for_seconds = (
            payload.muted_for_seconds
            if payload.muted_for_seconds is not None
            else self._settings.webhook_endpoint_auto_mute_seconds
        )
        if muted_for_seconds <= 0:
            raise HTTPException(status_code=400, detail="muted_for_seconds must be greater than 0.")
        muted_until = add_seconds_iso(muted_for_seconds)
        existing = self._get_webhook_endpoint_control(callback_url)
        control = self._upsert_webhook_endpoint_control(
            callback_url=callback_url,
            muted_until=muted_until,
            mute_reason=payload.reason or f"Operator muted endpoint for {muted_for_seconds}s.",
            consecutive_failure_count=int(existing.get("consecutive_failure_count") or 0) if existing else 0,
        )
        event_ids = [
            row["id"]
            for row in self._db.fetchall(
                "SELECT id FROM webhook_events WHERE status = ? AND callback_url = ?",
                (WEBHOOK_STATUS_QUEUED, callback_url),
            )
        ]
        for event_id in event_ids:
            self._webhooks.defer_event_until_mute(event_id)
        self._audit.log(
            event_type="webhook.endpoint.muted",
            resource_type="webhook_endpoint",
            resource_id=callback_url,
            actor=actor,
            payload=control.model_dump(),
        )
        return control

    def unmute_webhook_endpoint(
        self,
        payload: WebhookEndpointUnmuteRequest,
        *,
        actor: str = "system",
    ) -> WebhookEndpointControlResponse:
        callback_url = payload.callback_url.strip()
        if not callback_url:
            raise HTTPException(status_code=400, detail="callback_url is required.")
        existing = self._get_webhook_endpoint_control(callback_url)
        old_muted_until = existing.get("muted_until") if existing else None
        control = self._upsert_webhook_endpoint_control(
            callback_url=callback_url,
            muted_until=None,
            mute_reason=None,
            consecutive_failure_count=int(existing.get("consecutive_failure_count") or 0) if existing else 0,
        )
        if old_muted_until:
            releasable_rows = self._db.fetchall(
                """
                SELECT id
                FROM webhook_events
                WHERE status = ? AND callback_url = ? AND (available_at IS NULL OR available_at <= ?)
                ORDER BY created_at ASC, id ASC
                """,
                (WEBHOOK_STATUS_QUEUED, callback_url, old_muted_until),
            )
            now = utc_now_iso()
            for row in releasable_rows:
                self._db.execute(
                    """
                    UPDATE webhook_events
                    SET available_at = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (now, now, row["id"]),
                )
                self._webhooks.schedule_existing_event(row["id"])
        self._audit.log(
            event_type="webhook.endpoint.unmuted",
            resource_type="webhook_endpoint",
            resource_id=callback_url,
            actor=actor,
            payload=control.model_dump(),
        )
        return control

    def list_webhook_prune_history(self, *, limit: int = 20) -> list[WebhookPruneHistoryEntry]:
        if limit < 1 or limit > 100:
            raise HTTPException(status_code=400, detail="limit must be between 1 and 100.")
        rows = self._db.fetchall(
            """
            SELECT actor, payload_json, created_at
            FROM audit_events
            WHERE event_type = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            ("webhook.history.pruned", str(limit)),
        )
        history: list[WebhookPruneHistoryEntry] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            history.append(
                WebhookPruneHistoryEntry(
                    created_at=row["created_at"],
                    actor=row.get("actor"),
                    deleted_delivered_or_skipped=int(payload.get("deleted_delivered_or_skipped") or 0),
                    deleted_retry_history_events=int(payload.get("deleted_retry_history_events") or 0),
                    total_deleted=int(payload.get("total_deleted") or 0),
                    delivered_or_skipped_cutoff=payload.get("delivered_or_skipped_cutoff"),
                    retry_history_cutoff=payload.get("retry_history_cutoff"),
                )
            )
        return history

    def prune_webhook_history(self, *, emit_audit: bool = False, actor: str = "system") -> WebhookPruneResult:
        now = utc_now()
        delivered_or_skipped_cutoff: str | None = None
        retry_history_cutoff: str | None = None
        deleted_delivered_or_skipped = 0
        deleted_retry_history_events = 0

        if self._settings.webhook_event_retention_days > 0:
            delivered_cutoff_dt = now - timedelta(days=self._settings.webhook_event_retention_days)
            delivered_or_skipped_cutoff = delivered_cutoff_dt.isoformat().replace("+00:00", "Z")
            deleted_delivered_or_skipped = self._db.execute_rowcount(
                """
                DELETE FROM webhook_events
                WHERE status IN (?, ?)
                  AND retry_parent_id IS NULL
                  AND id NOT IN (
                    SELECT retry_parent_id FROM webhook_events WHERE retry_parent_id IS NOT NULL
                  )
                  AND updated_at < ?
                """,
                (WEBHOOK_STATUS_DELIVERED, WEBHOOK_STATUS_SKIPPED, delivered_or_skipped_cutoff),
            )

        if self._settings.webhook_retry_history_retention_days > 0:
            retry_cutoff_dt = now - timedelta(days=self._settings.webhook_retry_history_retention_days)
            retry_history_cutoff = retry_cutoff_dt.isoformat().replace("+00:00", "Z")
            rows = self._db.fetchall(
                """
                SELECT id, retry_parent_id, status, updated_at, dead_lettered_at
                FROM webhook_events
                WHERE callback_url IS NOT NULL
                """
            )
            rows_by_id = {row["id"]: row for row in rows}
            root_cache: dict[str, str] = {}

            def resolve_root_id(event_id: str) -> str:
                if event_id in root_cache:
                    return root_cache[event_id]
                row = rows_by_id[event_id]
                parent_id = row.get("retry_parent_id")
                if not parent_id or parent_id not in rows_by_id:
                    root_cache[event_id] = event_id
                else:
                    root_cache[event_id] = resolve_root_id(parent_id)
                return root_cache[event_id]

            chains: dict[str, list[dict[str, Any]]] = {}
            for row in rows:
                chains.setdefault(resolve_root_id(row["id"]), []).append(row)

            ids_to_delete: list[str] = []
            for chain_rows in chains.values():
                if not (
                    any(row.get("retry_parent_id") for row in chain_rows)
                    or any(row["status"] == WEBHOOK_STATUS_FAILED for row in chain_rows)
                    or any(row.get("dead_lettered_at") for row in chain_rows)
                ):
                    continue
                if any(row["status"] == WEBHOOK_STATUS_QUEUED for row in chain_rows):
                    continue
                latest_updated_at = max(parse_iso(row["updated_at"]) for row in chain_rows)
                if latest_updated_at >= retry_cutoff_dt:
                    continue
                ids_to_delete.extend(row["id"] for row in chain_rows)

            deleted_retry_history_events = self._delete_webhook_events(ids_to_delete)

        result = WebhookPruneResult(
            deleted_delivered_or_skipped=deleted_delivered_or_skipped,
            deleted_retry_history_events=deleted_retry_history_events,
            total_deleted=deleted_delivered_or_skipped + deleted_retry_history_events,
            delivered_or_skipped_cutoff=delivered_or_skipped_cutoff,
            retry_history_cutoff=retry_history_cutoff,
        )
        if emit_audit:
            self._audit.log(
                event_type="webhook.history.pruned",
                resource_type="webhook_event",
                resource_id=None,
                actor=actor,
                payload=result.model_dump(),
            )
        return result

    def redeliver_webhook_event(self, event_id: str) -> WebhookEventResponse:
        row = self._require_webhook_event(event_id)
        if row["status"] != WEBHOOK_STATUS_FAILED:
            raise HTTPException(status_code=400, detail="Only failed webhook events can be redelivered.")
        if not row.get("callback_url"):
            raise HTTPException(status_code=400, detail="Webhook event has no callback URL to redeliver.")
        redelivery_row = self._db.fetchone(
            """
            SELECT * FROM webhook_events
            WHERE retry_parent_id = ? AND status = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """,
            (row["id"], WEBHOOK_STATUS_QUEUED),
        )
        if redelivery_row:
            lease_expires_at = redelivery_row.get("lease_expires_at")
            if not lease_expires_at or parse_iso(lease_expires_at) <= utc_now():
                self._db.execute(
                    """
                    UPDATE webhook_events
                    SET available_at = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (utc_now_iso(), utc_now_iso(), redelivery_row["id"]),
                )
                redelivered = WebhookEventResponse(**self._require_webhook_event(redelivery_row["id"]))
                self._webhooks.schedule_existing_event(redelivery_row["id"])
            else:
                redelivered = WebhookEventResponse(**self._require_webhook_event(redelivery_row["id"]))
        else:
            redelivered = self._webhooks.dispatch(
                request_id=row["request_id"],
                event_type=row["event_type"],
                payload=json.loads(row["payload_json"]),
                callback_url=row["callback_url"],
                retry_parent_id=row["id"],
                retry_attempt=int(row.get("retry_attempt") or 0) + 1,
            )
        self._audit.log(
            event_type="webhook.event.redelivered",
            resource_type="webhook_event",
            resource_id=event_id,
            actor="system",
            payload={"redelivery_event_id": redelivered.id, "request_id": row["request_id"]},
        )
        return redelivered

    def retry_webhook_event_now(self, event_id: str) -> WebhookEventResponse:
        row = self._require_webhook_event(event_id)
        if row["status"] != WEBHOOK_STATUS_QUEUED:
            raise HTTPException(status_code=400, detail="Only queued webhook events can be retried immediately.")
        if not row.get("callback_url"):
            raise HTTPException(status_code=400, detail="Webhook event has no callback URL to retry.")
        lease_expires_at = row.get("lease_expires_at")
        if lease_expires_at and parse_iso(lease_expires_at) > utc_now():
            raise HTTPException(status_code=409, detail="Webhook event is currently leased by an active delivery worker.")
        self._db.execute(
            """
            UPDATE webhook_events
            SET available_at = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
            WHERE id = ?
            """,
            (utc_now_iso(), utc_now_iso(), event_id),
        )
        self._audit.log(
            event_type="webhook.event.retry_now",
            resource_type="webhook_event",
            resource_id=event_id,
            actor="system",
            payload={"request_id": row["request_id"]},
        )
        retried = WebhookEventResponse(**self._require_webhook_event(event_id))
        self._webhooks.schedule_existing_event(event_id)
        return retried

    def recover_queued_webhook_events(self) -> int:
        return self._webhooks.recover_queued_events()

    def start_webhook_recovery_loop(self) -> None:
        self._webhooks.start_recovery_loop()

    def _approval_url(self, request_id: str) -> str:
        return f"{self._settings.base_url}/approve/{request_id}"

    def _start_login_for_approver(self, approver_id: str) -> AdminLoginStartResponse:
        credential_rows = self._db.fetchall(
            "SELECT credential_id FROM webauthn_credentials WHERE approver_id = ?",
            (approver_id,),
        )
        if not credential_rows:
            raise HTTPException(status_code=400, detail="Approver has no passkey credentials enrolled.")
        options, challenge = self._webauthn.generate_authentication(
            allowed_credential_ids=[row["credential_id"] for row in credential_rows]
        )
        session_id = stable_id("approver_login")
        self._db.execute(
            """
            INSERT INTO approver_login_sessions(id, approver_id, challenge, options_json, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                approver_id,
                challenge,
                json_dumps(options),
                add_minutes_iso(self._settings.challenge_ttl_minutes),
                utc_now_iso(),
            ),
        )
        return AdminLoginStartResponse(session_id=session_id, public_key_options=options)

    def _verify_authentication_proof(self, approver_id: str, challenge: str, credential: dict[str, Any]) -> None:
        if not isinstance(credential, dict):
            raise HTTPException(status_code=400, detail="WebAuthn credential is required.")
        credential_id = str(credential.get("id") or credential.get("rawId") or "").strip()
        if not credential_id:
            raise HTTPException(status_code=400, detail="WebAuthn credential id missing in proof.")
        credential_row = self._db.fetchone(
            """
            SELECT * FROM webauthn_credentials
            WHERE approver_id = ? AND credential_id = ?
            """,
            (approver_id, credential_id),
        )
        if not credential_row:
            raise HTTPException(status_code=400, detail="Credential not enrolled for the approver.")
        try:
            new_sign_count = self._webauthn.verify_authentication(
                credential=credential,
                challenge=challenge,
                credential_public_key=credential_row["public_key"],
                credential_current_sign_count=int(credential_row["sign_count"]),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        self._db.execute(
            """
            UPDATE webauthn_credentials
            SET sign_count = ?, last_used_at = ?
            WHERE id = ?
            """,
            (new_sign_count, utc_now_iso(), credential_row["id"]),
        )

    def _issue_approver_session(self, approver_id: str) -> tuple[str, str]:
        session_id = stable_id("approversess")
        csrf_token = token_urlsafe(18)
        now = utc_now_iso()
        self._db.execute(
            """
            INSERT INTO approver_sessions(id, approver_id, csrf_token, expires_at, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                approver_id,
                csrf_token,
                add_minutes_iso(self._settings.admin_session_ttl_minutes),
                now,
                now,
            ),
        )
        return session_id, csrf_token

    def _issue_admin_session(self, admin_id: str) -> tuple[str, str]:
        session_id = stable_id("adminsess")
        csrf_token = token_urlsafe(18)
        now = utc_now_iso()
        self._db.execute(
            """
            INSERT INTO admin_sessions(id, admin_id, csrf_token, expires_at, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                admin_id,
                csrf_token,
                add_minutes_iso(self._settings.admin_session_ttl_minutes),
                now,
                now,
            ),
        )
        return session_id, csrf_token

    def _issue_session_for_approver(self, approver_id: str) -> tuple[str, str]:
        admin = self._get_admin_by_approver_id(approver_id)
        if admin:
            return self._issue_admin_session(admin["id"])
        return self._issue_approver_session(approver_id)

    def _require_single_admin(self) -> dict[str, Any]:
        row = self._db.fetchone(
            """
            SELECT a.id, a.approver_id, p.email, p.display_name
            FROM admins a
            JOIN approvers p ON p.id = a.approver_id
            ORDER BY a.created_at ASC, a.id ASC
            LIMIT 1
            """
        )
        if not row:
            raise HTTPException(status_code=400, detail="ClawPass is not initialized.")
        return row

    def _require_admin(self, admin_id: str) -> dict[str, Any]:
        row = self._db.fetchone(
            """
            SELECT a.id, a.approver_id, p.email, p.display_name
            FROM admins a
            JOIN approvers p ON p.id = a.approver_id
            WHERE a.id = ?
            """,
            (admin_id,),
        )
        if not row:
            raise HTTPException(status_code=404, detail="Admin not found.")
        return row

    def _get_admin_by_approver_id(self, approver_id: str) -> dict[str, Any] | None:
        return self._db.fetchone(
            """
            SELECT a.id, a.approver_id, p.email, p.display_name
            FROM admins a
            JOIN approvers p ON p.id = a.approver_id
            WHERE a.approver_id = ?
            """,
            (approver_id,),
        )

    def _require_producer(self, producer_id: str) -> dict[str, Any]:
        row = self._db.fetchone("SELECT * FROM producers WHERE id = ?", (producer_id,))
        if not row:
            raise HTTPException(status_code=404, detail="Producer not found.")
        return row

    def _get_webhook_endpoint_control(self, callback_url: str) -> dict[str, Any] | None:
        return self._db.fetchone(
            "SELECT * FROM webhook_endpoint_controls WHERE callback_url = ?",
            (callback_url,),
        )

    def _upsert_webhook_endpoint_control(
        self,
        *,
        callback_url: str,
        muted_until: str | None,
        mute_reason: str | None,
        consecutive_failure_count: int,
    ) -> WebhookEndpointControlResponse:
        now = utc_now_iso()
        self._db.execute(
            """
            INSERT INTO webhook_endpoint_controls(
              callback_url, muted_until, mute_reason, consecutive_failure_count, updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(callback_url) DO UPDATE SET
              muted_until = excluded.muted_until,
              mute_reason = excluded.mute_reason,
              consecutive_failure_count = excluded.consecutive_failure_count,
              updated_at = excluded.updated_at
            """,
            (callback_url, muted_until, mute_reason, consecutive_failure_count, now),
        )
        row = self._get_webhook_endpoint_control(callback_url)
        return WebhookEndpointControlResponse(
            callback_url=callback_url,
            muted_until=row.get("muted_until"),
            mute_reason=row.get("mute_reason"),
            consecutive_failure_count=int(row.get("consecutive_failure_count") or 0),
        )

    def _delete_webhook_events(self, event_ids: list[str]) -> int:
        if not event_ids:
            return 0
        deleted = 0
        unique_ids = list(dict.fromkeys(event_ids))
        for start in range(0, len(unique_ids), 200):
            batch = unique_ids[start : start + 200]
            placeholders = ",".join("?" for _ in batch)
            deleted += self._db.execute_rowcount(
                f"DELETE FROM webhook_events WHERE id IN ({placeholders})",
                tuple(batch),
            )
        return deleted

    def _require_webhook_event(self, event_id: str) -> dict[str, Any]:
        row = self._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", (event_id,))
        if not row:
            raise HTTPException(status_code=404, detail="Webhook event not found.")
        return row

    def list_approval_requests(
        self,
        *,
        status: str | None = None,
        producer_id: str | None = None,
    ) -> list[ApprovalRequestResponse]:
        self._expire_pending_requests()
        clauses: list[str] = []
        params: list[str] = []
        if status:
            normalized_status = status.upper()
            if normalized_status not in VALID_APPROVAL_STATUSES:
                raise HTTPException(status_code=400, detail=f"Unsupported status '{status}'.")
            clauses.append("status = ?")
            params.append(normalized_status)
        if producer_id:
            clauses.append("producer_id = ?")
            params.append(producer_id)
        query = "SELECT * FROM approval_requests"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT 200"
        rows = self._db.fetchall(query, tuple(params))
        return [self._to_approval_response(row) for row in rows]

    def _emit_request_event(self, row: dict[str, Any], event_type: str) -> None:
        payload = {
            "request_id": row["id"],
            "producer_id": row.get("producer_id"),
            "event_type": event_type,
            "status": row["status"],
            "decision": row.get("decision"),
            "method": row.get("method"),
            "approver_id": row.get("approver_id"),
            "action_hash": row["action_hash"],
            "action_type": row["action_type"],
            "action_ref": row.get("action_ref"),
            "risk_level": row["risk_level"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "decided_at": row.get("decided_at"),
            "nonce": row["nonce"],
            "metadata": json.loads(row["metadata_json"]),
            "approval_url": self._approval_url(row["id"]),
        }
        self._webhooks.dispatch(
            request_id=row["id"],
            event_type=event_type,
            payload=payload,
            callback_url=row.get("callback_url"),
        )

    def _count_passkeys(self, approver_id: str) -> int:
        row = self._db.fetchone(
            "SELECT COUNT(*) AS count FROM webauthn_credentials WHERE approver_id = ? AND is_ledger = 0",
            (approver_id,),
        )
        return int(row["count"])

    def _require_request(self, request_id: str) -> dict[str, Any]:
        row = self._db.fetchone("SELECT * FROM approval_requests WHERE id = ?", (request_id,))
        if not row:
            raise HTTPException(status_code=404, detail="Approval request not found.")
        return row

    def _require_invite(self, token: str) -> dict[str, Any]:
        invite = self._db.fetchone("SELECT * FROM approver_invites WHERE token = ?", (token,))
        if not invite:
            raise HTTPException(status_code=404, detail="Invite not found.")
        if invite.get("consumed_at"):
            raise HTTPException(status_code=400, detail="Invite already used.")
        if parse_iso(invite["expires_at"]) <= utc_now():
            raise HTTPException(status_code=400, detail="Invite expired.")
        return invite

    def _expire_pending_requests(self) -> None:
        now = utc_now_iso()
        pending_rows = self._db.fetchall(
            "SELECT * FROM approval_requests WHERE status = ? AND expires_at <= ?",
            (APPROVAL_STATUS_PENDING, now),
        )
        for row in pending_rows:
            self._expire_if_needed(row)

    def _expire_if_needed(self, row: dict[str, Any]) -> dict[str, Any]:
        if row["status"] != APPROVAL_STATUS_PENDING:
            return row
        if parse_iso(row["expires_at"]) > utc_now():
            return row
        self._db.execute(
            "UPDATE approval_requests SET status = ?, decision = ?, decided_at = ? WHERE id = ?",
            (APPROVAL_STATUS_EXPIRED, "EXPIRED", utc_now_iso(), row["id"]),
        )
        updated = self._require_request(row["id"])
        self._emit_request_event(updated, EVENT_APPROVAL_EXPIRED)
        self._audit.log(
            event_type="approval.request.expired",
            resource_type="approval_request",
            resource_id=row["id"],
            actor="system",
            payload={"expired_at": updated["decided_at"]},
        )
        return updated

    def _ensure_approver(self, payload: ApproverIdentityIn, *, require_existing: bool = False) -> dict[str, Any]:
        if payload.approver_id:
            approver = self._db.fetchone("SELECT * FROM approvers WHERE id = ?", (payload.approver_id,))
            if approver:
                return approver
            if require_existing:
                raise HTTPException(status_code=404, detail="Approver id not found.")

        if payload.email:
            existing = self._db.fetchone("SELECT * FROM approvers WHERE LOWER(email) = LOWER(?)", (payload.email,))
            if existing:
                if payload.display_name and payload.display_name != existing.get("display_name"):
                    self._db.execute(
                        "UPDATE approvers SET display_name = ? WHERE id = ?",
                        (payload.display_name, existing["id"]),
                    )
                    existing["display_name"] = payload.display_name
                return existing

        if require_existing:
            raise HTTPException(status_code=400, detail="Approver identity is missing or unknown.")

        if not payload.email:
            raise HTTPException(status_code=400, detail="Approver email is required to create a new approver.")

        approver_id = payload.approver_id or stable_id("approver")
        now = utc_now_iso()
        self._db.execute(
            "INSERT INTO approvers(id, email, display_name, created_at) VALUES (?, ?, ?, ?)",
            (approver_id, payload.email.lower(), payload.display_name, now),
        )
        self._audit.log(
            event_type="approver.created",
            resource_type="approver",
            resource_id=approver_id,
            actor=approver_id,
            payload={"email": payload.email.lower()},
        )
        return self._db.fetchone("SELECT * FROM approvers WHERE id = ?", (approver_id,))

    def _to_approver_invite_response(self, row: dict[str, Any]) -> ApproverInviteResponse:
        return ApproverInviteResponse(
            token=row["token"],
            approver_id=row["approver_id"],
            email=row["email"],
            display_name=row.get("display_name"),
            invite_url=f"{self._settings.base_url}/invites/{row['token']}",
            expires_at=row["expires_at"],
            consumed_at=row.get("consumed_at"),
        )

    def _to_approval_response(self, row: dict[str, Any]) -> ApprovalRequestResponse:
        return ApprovalRequestResponse(
            id=row["id"],
            producer_id=row.get("producer_id"),
            action_type=row["action_type"],
            action_ref=row.get("action_ref"),
            action_hash=row["action_hash"],
            requester_id=row.get("requester_id"),
            risk_level=row["risk_level"],
            metadata=json.loads(row["metadata_json"]),
            status=row["status"],
            decision=row.get("decision"),
            method=row.get("method"),
            approver_id=row.get("approver_id"),
            nonce=row["nonce"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            decided_at=row.get("decided_at"),
            callback_url=row.get("callback_url"),
            approval_url=self._approval_url(row["id"]),
        )
