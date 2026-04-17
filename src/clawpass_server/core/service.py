from __future__ import annotations

import json
import sqlite3
from datetime import timezone
from typing import Any

from fastapi import HTTPException

from clawpass_server.adapters.ethereum_adapter import EthereumAdapter
from clawpass_server.adapters.webauthn_adapter import WebAuthnAdapter
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
)
from clawpass_server.core.database import Database
from clawpass_server.core.policy import PolicyEngine
from clawpass_server.core.schemas import (
    ApprovalRequestResponse,
    ApproverIdentityIn,
    ApproverSummary,
    CreateApprovalRequest,
    DecisionCompleteRequest,
    DecisionStartRequest,
    DecisionStartResponse,
    EthereumSignerChallengeRequest,
    EthereumSignerChallengeResponse,
    EthereumSignerVerifyRequest,
    EthereumSignerVerifyResponse,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterCompleteResponse,
    WebAuthnRegisterStartRequest,
    WebAuthnRegisterStartResponse,
    WebhookEventResponse,
)
from clawpass_server.core.utils import add_minutes_iso, json_dumps, parse_iso, stable_id, token_urlsafe, utc_now, utc_now_iso
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

    def create_approval_request(self, payload: CreateApprovalRequest) -> ApprovalRequestResponse:
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
                  id, action_type, action_ref, action_hash, requester_id, risk_level, metadata_json, status,
                  decision, approver_id, method, created_at, expires_at, decided_at, nonce, callback_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, NULL, ?, ?)
                """,
                (
                    request_id,
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
            actor=payload.requester_id,
            payload={"risk_level": risk_level, "action_type": payload.action_type},
        )
        return self._to_approval_response(row)

    def get_approval_request(self, request_id: str) -> ApprovalRequestResponse:
        row = self._require_request(request_id)
        row = self._expire_if_needed(row)
        return self._to_approval_response(row)

    def cancel_approval_request(self, request_id: str, *, reason: str | None) -> ApprovalRequestResponse:
        row = self._require_request(request_id)
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
            actor="system",
            payload={"reason": reason},
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

    def list_webhook_events(self, request_id: str | None = None) -> list[WebhookEventResponse]:
        if request_id:
            rows = self._db.fetchall(
                "SELECT * FROM webhook_events WHERE request_id = ? ORDER BY created_at DESC",
                (request_id,),
            )
        else:
            rows = self._db.fetchall("SELECT * FROM webhook_events ORDER BY created_at DESC LIMIT 200")
        return [WebhookEventResponse(**row) for row in rows]

    def list_approval_requests(self, *, status: str | None = None) -> list[ApprovalRequestResponse]:
        self._expire_pending_requests()
        if status:
            normalized_status = status.upper()
            if normalized_status not in VALID_APPROVAL_STATUSES:
                raise HTTPException(status_code=400, detail=f"Unsupported status '{status}'.")
            rows = self._db.fetchall(
                "SELECT * FROM approval_requests WHERE status = ? ORDER BY created_at DESC LIMIT 200",
                (normalized_status,),
            )
        else:
            rows = self._db.fetchall("SELECT * FROM approval_requests ORDER BY created_at DESC LIMIT 200")
        return [self._to_approval_response(row) for row in rows]

    def _emit_request_event(self, row: dict[str, Any], event_type: str) -> None:
        payload = {
            "request_id": row["id"],
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

    def _to_approval_response(self, row: dict[str, Any]) -> ApprovalRequestResponse:
        return ApprovalRequestResponse(
            id=row["id"],
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
        )


LedgerClawService = ClawPassService
