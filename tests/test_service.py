from __future__ import annotations

from datetime import timedelta

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import HTTPException

from ledgerclaw_server.core.schemas import (
    CreateApprovalRequest,
    DecisionCompleteRequest,
    DecisionStartRequest,
    EthereumSignerChallengeRequest,
    EthereumSignerVerifyRequest,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterStartRequest,
)
from ledgerclaw_server.core.utils import utc_now


def _enroll_passkey(service, *, email: str, is_ledger: bool = False) -> str:
    start = service.start_webauthn_registration(
        WebAuthnRegisterStartRequest(email=email, display_name="Test", is_ledger=is_ledger)
    )
    service.complete_webauthn_registration(
        WebAuthnRegisterCompleteRequest(
            session_id=start.session_id,
            credential={"id": f"cred-{email}-{is_ledger}", "response": {}},
        )
    )
    return start.approver_id


def test_high_risk_requires_non_ledger_passkey(service):
    start = service.start_webauthn_registration(
        WebAuthnRegisterStartRequest(email="ops@example.org", display_name="Ops", is_ledger=True)
    )

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="outbound.send",
            action_hash="sha256:abc",
            risk_level="high",
            requester_id="producer",
        )
    )

    with pytest.raises(HTTPException) as exc:
        service.start_decision(
            request.id,
            DecisionStartRequest(approver_id=start.approver_id, decision="APPROVE", method="ledger_webauthn"),
        )

    assert exc.value.status_code == 400
    assert "at least one enrolled passkey" in str(exc.value.detail)


def test_passkey_enrollment_allows_high_risk_decision(service):
    approver_id = _enroll_passkey(service, email="director@example.org", is_ledger=False)

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="outbound.send",
            action_hash="sha256:ready",
            risk_level="high",
            requester_id="producer",
        )
    )

    start = service.start_decision(
        request.id,
        DecisionStartRequest(approver_id=approver_id, decision="APPROVE", method="webauthn"),
    )
    completed = service.complete_decision(
        request.id,
        DecisionCompleteRequest(challenge_id=start.challenge_id, proof={"credential": {"id": "cred-director@example.org-False"}}),
    )

    assert completed.status == "APPROVED"
    assert completed.method == "webauthn"


def test_hash_binding_rejects_tampered_request(service):
    approver_id = _enroll_passkey(service, email="ops2@example.org", is_ledger=False)

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="risky.op",
            action_hash="sha256:original",
            risk_level="medium",
        )
    )
    start = service.start_decision(
        request.id,
        DecisionStartRequest(approver_id=approver_id, decision="APPROVE", method="webauthn"),
    )

    # Simulate upstream tamper/drift between start and complete.
    service._db.execute("UPDATE approval_requests SET action_hash = ? WHERE id = ?", ("sha256:tampered", request.id))

    with pytest.raises(HTTPException) as exc:
        service.complete_decision(
            request.id,
            DecisionCompleteRequest(challenge_id=start.challenge_id, proof={"credential": {"id": "cred-ops2@example.org-False"}}),
        )

    assert exc.value.status_code == 400
    assert "hash/nonce binding" in str(exc.value.detail)


def test_expired_request_transitions_and_emits_event(service):
    request = service.create_approval_request(
        CreateApprovalRequest(action_type="digest.publish", action_hash="sha256:exp", risk_level="low")
    )

    expired_at = (utc_now() - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    service._db.execute("UPDATE approval_requests SET expires_at = ? WHERE id = ?", (expired_at, request.id))

    current = service.get_approval_request(request.id)
    assert current.status == "EXPIRED"

    events = service.list_webhook_events(request.id)
    event_types = {event.event_type for event in events}
    assert "approval.pending" in event_types
    assert "approval.expired" in event_types


def test_cancel_request_emits_cancelled_event(service):
    request = service.create_approval_request(
        CreateApprovalRequest(action_type="digest.publish", action_hash="sha256:cancel", risk_level="low")
    )

    cancelled = service.cancel_approval_request(request.id, reason="operator cancelled")
    assert cancelled.status == "CANCELLED"
    assert cancelled.decision == "CANCELLED"
    assert cancelled.method == "system"

    events = service.list_webhook_events(request.id)
    event_types = {event.event_type for event in events}
    assert "approval.pending" in event_types
    assert "approval.cancelled" in event_types


def test_duplicate_request_id_returns_conflict(service):
    payload = CreateApprovalRequest(
        request_id="req-fixed-id",
        action_type="digest.publish",
        action_hash="sha256:first",
        risk_level="low",
    )
    service.create_approval_request(payload)

    with pytest.raises(HTTPException) as exc:
        service.create_approval_request(
            CreateApprovalRequest(
                request_id="req-fixed-id",
                action_type="digest.publish",
                action_hash="sha256:second",
                risk_level="low",
            )
        )

    assert exc.value.status_code == 409
    assert "already exists" in str(exc.value.detail)


def test_invalid_expires_at_returns_bad_request(service):
    with pytest.raises(HTTPException) as exc:
        service.create_approval_request(
            CreateApprovalRequest(
                action_type="digest.publish",
                action_hash="sha256:bad-expiry",
                risk_level="low",
                expires_at="not-a-timestamp",
            )
        )

    assert exc.value.status_code == 400
    assert "valid ISO 8601" in str(exc.value.detail)


def test_naive_expires_at_is_treated_as_utc(service):
    future_naive = (utc_now() + timedelta(minutes=5)).replace(tzinfo=None).isoformat(timespec="seconds")
    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="digest.publish",
            action_hash="sha256:naive-expiry",
            risk_level="low",
            expires_at=future_naive,
        )
    )

    assert request.status == "PENDING"
    assert request.expires_at.endswith("Z")


def test_list_approval_requests_status_filter_respects_expiration(service):
    active = service.create_approval_request(
        CreateApprovalRequest(action_type="digest.publish", action_hash="sha256:pending", risk_level="low")
    )
    expired = service.create_approval_request(
        CreateApprovalRequest(action_type="digest.publish", action_hash="sha256:expired", risk_level="low")
    )

    expired_at = (utc_now() - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    service._db.execute("UPDATE approval_requests SET expires_at = ? WHERE id = ?", (expired_at, expired.id))

    pending_ids = {request.id for request in service.list_approval_requests(status="PENDING")}
    assert active.id in pending_ids
    assert expired.id not in pending_ids

    expired_ids = {request.id for request in service.list_approval_requests(status="EXPIRED")}
    assert expired.id in expired_ids
    assert active.id not in expired_ids

    lower_pending_ids = {request.id for request in service.list_approval_requests(status="pending")}
    assert active.id in lower_pending_ids
    assert expired.id not in lower_pending_ids


def test_list_approval_requests_rejects_unknown_status(service):
    with pytest.raises(HTTPException) as exc:
        service.list_approval_requests(status="unknown")

    assert exc.value.status_code == 400
    assert "Unsupported status" in str(exc.value.detail)


def test_ethereum_signer_enrollment_and_decision(service):
    account = Account.create()
    challenge = service.start_ethereum_signer_challenge(
        EthereumSignerChallengeRequest(
            email="wallet@example.org",
            display_name="Wallet",
            address=account.address,
            chain_id=1,
        )
    )

    enrollment_signable = encode_typed_data(full_message=challenge.typed_data)
    enrollment_signature = Account.sign_message(enrollment_signable, account.key).signature.hex()

    verify = service.verify_ethereum_signer(
        EthereumSignerVerifyRequest(session_id=challenge.session_id, signature=enrollment_signature)
    )
    assert verify.address == account.address.lower()

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="finance.release",
            action_hash="sha256:eth",
            risk_level="medium",
            requester_id="producer",
        )
    )
    decision_start = service.start_decision(
        request.id,
        DecisionStartRequest(approver_id=challenge.approver_id, decision="APPROVE", method="ethereum_signer"),
    )

    decision_signable = encode_typed_data(full_message=decision_start.payload["typed_data"])
    decision_signature = Account.sign_message(decision_signable, account.key).signature.hex()

    result = service.complete_decision(
        request.id,
        DecisionCompleteRequest(challenge_id=decision_start.challenge_id, proof={"signature": decision_signature}),
    )

    assert result.status == "APPROVED"
    assert result.method == "ethereum_signer"


def test_ledger_webauthn_method_works_when_credential_exists(service):
    approver_id = _enroll_passkey(service, email="ledger@example.org", is_ledger=True)
    request = service.create_approval_request(
        CreateApprovalRequest(action_type="deploy.rollout", action_hash="sha256:ledger", risk_level="medium")
    )

    start = service.start_decision(
        request.id,
        DecisionStartRequest(approver_id=approver_id, decision="APPROVE", method="ledger_webauthn"),
    )
    result = service.complete_decision(
        request.id,
        DecisionCompleteRequest(challenge_id=start.challenge_id, proof={"credential": {"id": "cred-ledger@example.org-True"}}),
    )

    assert result.status == "APPROVED"
    assert result.method == "ledger_webauthn"
