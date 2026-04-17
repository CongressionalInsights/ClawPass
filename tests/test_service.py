from __future__ import annotations

from datetime import timedelta

import pytest
import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data
from fastapi import HTTPException

from clawpass_server.core.schemas import (
    CreateApprovalRequest,
    DecisionCompleteRequest,
    DecisionStartRequest,
    EthereumSignerChallengeRequest,
    EthereumSignerVerifyRequest,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterStartRequest,
)
from clawpass_server.core.utils import utc_now


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


def test_webhook_delivery_retries_once_on_transient_failure(monkeypatch, service):
    attempts = {"count": 0}

    class RetryingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise httpx.TimeoutException("timed out")
            return httpx.Response(204, request=httpx.Request("POST", url))

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", RetryingClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: task())

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="digest.publish",
            action_hash="sha256:webhook-retry",
            risk_level="low",
            callback_url="https://example.com/webhooks",
        )
    )

    events = service.list_webhook_events(request.id)
    assert attempts["count"] == 2
    assert events[0].event_type == "approval.pending"
    assert events[0].status == "delivered"
    assert events[0].attempt_count == 2
    assert events[0].last_error is None


def test_webhook_delivery_does_not_retry_non_retryable_http_error(monkeypatch, service):
    attempts = {"count": 0}

    class FailingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            attempts["count"] += 1
            request = httpx.Request("POST", url)
            response = httpx.Response(400, request=request)
            raise httpx.HTTPStatusError("bad request", request=request, response=response)

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", FailingClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: task())

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="digest.publish",
            action_hash="sha256:webhook-fail",
            risk_level="low",
            callback_url="https://example.com/webhooks",
        )
    )

    events = service.list_webhook_events(request.id)
    assert attempts["count"] == 1
    assert events[0].event_type == "approval.pending"
    assert events[0].status == "failed"
    assert events[0].attempt_count == 1
    assert events[0].last_error == "bad request"


def test_list_webhook_events_supports_status_event_type_and_cursor(monkeypatch, service):
    deliveries = {"count": 0}

    class FlakyClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            deliveries["count"] += 1
            request = httpx.Request("POST", url)
            if deliveries["count"] == 1:
                response = httpx.Response(400, request=request)
                raise httpx.HTTPStatusError("bad request", request=request, response=response)
            return httpx.Response(204, request=request)

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", FlakyClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: task())

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="digest.publish",
            action_hash="sha256:webhook-filter",
            risk_level="low",
            callback_url="https://example.com/webhooks",
        )
    )
    service.cancel_approval_request(request.id, reason="operator cancelled")

    second = service.create_approval_request(
        CreateApprovalRequest(action_type="digest.publish", action_hash="sha256:webhook-filter-2", risk_level="low")
    )
    service.cancel_approval_request(second.id, reason="operator cancelled")

    failed_events = service.list_webhook_events(request.id, status="FAILED", event_type="approval.pending")
    assert len(failed_events) == 1
    assert failed_events[0].status == "failed"
    assert failed_events[0].event_type == "approval.pending"

    first_page = service.list_webhook_events(status="skipped", limit=1)
    assert len(first_page) == 1
    second_page = service.list_webhook_events(status="skipped", limit=10, cursor=first_page[0].id)
    second_page_ids = {event.id for event in second_page}
    assert first_page[0].id not in second_page_ids


def test_redeliver_failed_webhook_event_creates_new_delivery_record(monkeypatch, service):
    deliveries = {"count": 0}

    class FlakyClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            deliveries["count"] += 1
            request = httpx.Request("POST", url)
            if deliveries["count"] == 1:
                response = httpx.Response(400, request=request)
                raise httpx.HTTPStatusError("bad request", request=request, response=response)
            return httpx.Response(204, request=request)

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", FlakyClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: task())

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="digest.publish",
            action_hash="sha256:webhook-redeliver",
            risk_level="low",
            callback_url="https://example.com/webhooks",
        )
    )
    failed_event = service.list_webhook_events(request.id, status="failed")[0]

    redelivered = service.redeliver_webhook_event(failed_event.id)

    assert redelivered.id != failed_event.id
    assert redelivered.request_id == request.id
    assert redelivered.event_type == "approval.pending"
    assert redelivered.status == "queued"

    delivered_events = service.list_webhook_events(request.id, status="delivered", event_type="approval.pending")
    delivered_ids = {event.id for event in delivered_events}
    assert redelivered.id in delivered_ids


def test_redeliver_rejects_non_failed_webhook_event(service):
    request = service.create_approval_request(
        CreateApprovalRequest(action_type="digest.publish", action_hash="sha256:webhook-skip", risk_level="low")
    )
    event = service.list_webhook_events(request.id)[0]

    with pytest.raises(HTTPException) as exc:
        service.redeliver_webhook_event(event.id)

    assert exc.value.status_code == 400
    assert "Only failed webhook events" in str(exc.value.detail)


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
