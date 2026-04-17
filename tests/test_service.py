from __future__ import annotations

import json
from dataclasses import replace
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
    WebhookEndpointMuteRequest,
    WebhookEndpointUnmuteRequest,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterStartRequest,
)
from clawpass_server.core.database import Database
from clawpass_server.core.utils import parse_iso, utc_now
from clawpass_server.core.webhooks import WebhookDispatcher


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
    assert events[0].dead_lettered_at is None


def test_webhook_delivery_summary_reports_backlog_failure_rate_and_redeliveries(monkeypatch, service):
    queued_at = (utc_now() - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    service._db.execute(
        """
        INSERT INTO webhook_events(
          id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count, lease_owner, lease_expires_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "whevt-backlog",
            "req-backlog",
            "approval.pending",
            json.dumps({"request_id": "req-backlog"}),
            "https://example.com/webhooks",
            "queued",
            None,
            0,
            None,
            None,
            queued_at,
            queued_at,
        ),
    )

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
            action_hash="sha256:webhook-summary",
            risk_level="low",
            callback_url="https://example.com/webhooks",
        )
    )
    failed_event = service.list_webhook_events(request.id, status="failed")[0]
    service.redeliver_webhook_event(failed_event.id)

    summary = service.get_webhook_delivery_summary()
    assert summary.total_events == 3
    assert summary.backlog_count == 1
    assert summary.leased_backlog_count == 0
    assert summary.stalled_backlog_count == 1
    assert summary.scheduled_retry_count == 0
    assert summary.delivered_count == 1
    assert summary.failed_count == 1
    assert summary.skipped_count == 0
    assert summary.attempted_count == 2
    assert summary.failure_rate == 0.5
    assert summary.redelivery_count == 1
    assert summary.redelivery_backlog_count == 0
    assert summary.redelivery_delivered_count == 1
    assert summary.redelivery_failed_count == 0
    assert summary.oldest_queued_at == queued_at
    assert summary.oldest_stalled_at == queued_at
    assert summary.last_event_at is not None
    assert summary.health_state == "warning"
    assert len(summary.alerts) == 2
    assert "stalled event" in summary.alerts[0]
    assert "failure rate" in summary.alerts[1]


def test_webhook_endpoint_summaries_group_failures_by_callback_url(service):
    now = utc_now()
    future_available_at = (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    old_created_at = (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    current_created_at = now.isoformat().replace("+00:00", "Z")
    service._db.execute_many(
        [
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-endpoint-delivered",
                    "req-endpoint",
                    "approval.pending",
                    json.dumps({"request_id": "req-endpoint"}),
                    "https://example.com/webhooks/a",
                    "delivered",
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    old_created_at,
                    old_created_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-endpoint-dead",
                    "req-endpoint",
                    "approval.pending",
                    json.dumps({"request_id": "req-endpoint"}),
                    "https://example.com/webhooks/a",
                    "failed",
                    "upstream timeout",
                    2,
                    None,
                    None,
                    None,
                    None,
                    1,
                    current_created_at,
                    "Automatic retry budget exhausted after 1 queued retry.",
                    current_created_at,
                    current_created_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-endpoint-queued",
                    "req-endpoint",
                    "approval.pending",
                    json.dumps({"request_id": "req-endpoint"}),
                    "https://example.com/webhooks/a",
                    "queued",
                    None,
                    0,
                    None,
                    None,
                    future_available_at,
                    "whevt-endpoint-dead",
                    2,
                    None,
                    None,
                    current_created_at,
                    current_created_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-endpoint-healthy",
                    "req-endpoint-b",
                    "approval.pending",
                    json.dumps({"request_id": "req-endpoint-b"}),
                    "https://example.com/webhooks/b",
                    "delivered",
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    current_created_at,
                    current_created_at,
                ),
            ),
        ]
    )

    summaries = service.list_webhook_endpoint_summaries(limit=10)
    assert summaries[0].callback_url == "https://example.com/webhooks/a"
    assert summaries[0].health_state == "critical"
    assert summaries[0].total_events == 3
    assert summaries[0].queued_count == 1
    assert summaries[0].delivered_count == 1
    assert summaries[0].failed_count == 1
    assert summaries[0].dead_lettered_count == 1
    assert summaries[0].attempted_count == 2
    assert summaries[0].failure_rate == 0.5
    assert summaries[0].next_attempt_at == future_available_at
    assert summaries[0].latest_error == "upstream timeout"
    assert summaries[1].callback_url == "https://example.com/webhooks/b"
    assert summaries[1].health_state == "healthy"


def test_failed_delivery_auto_mutes_endpoint_and_delays_retry(monkeypatch, service):
    service._settings.webhook_endpoint_auto_mute_threshold = 1
    service._settings.webhook_endpoint_auto_mute_seconds = 600
    tasks = []

    class FailingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            request = httpx.Request("POST", url)
            response = httpx.Response(503, request=request)
            raise httpx.HTTPStatusError("service unavailable", request=request, response=response)

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", FailingClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: tasks.append(task))

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="digest.publish",
            action_hash="sha256:auto-mute",
            risk_level="low",
            callback_url="https://example.com/webhooks/auto-mute",
        )
    )
    assert len(tasks) == 1
    tasks[0]()

    summaries = service.list_webhook_endpoint_summaries(limit=10)
    endpoint = next(summary for summary in summaries if summary.callback_url.endswith("/auto-mute"))
    assert endpoint.health_state == "warning"
    assert endpoint.muted_until is not None
    assert endpoint.mute_reason is not None
    assert "Automatically muted" in endpoint.mute_reason
    assert endpoint.consecutive_failure_count == 1

    queued = service.list_webhook_events(request.id, status="queued")
    assert len(queued) == 1
    assert queued[0].available_at is not None
    assert parse_iso(queued[0].available_at) >= parse_iso(endpoint.muted_until)


def test_manual_mute_unmute_and_prune_history(service, monkeypatch):
    callback_url = "https://example.com/webhooks/manual"
    created_at = (utc_now() - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    available_at = (utc_now() - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    old_delivered_at = (utc_now() - timedelta(days=20)).isoformat().replace("+00:00", "Z")
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: None)

    service._db.execute_many(
        [
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-manual-queued",
                    "req-manual-queued",
                    "approval.pending",
                    json.dumps({"request_id": "req-manual-queued"}),
                    callback_url,
                    "queued",
                    None,
                    0,
                    None,
                    None,
                    available_at,
                    None,
                    0,
                    None,
                    None,
                    created_at,
                    created_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-manual-old",
                    "req-manual-old",
                    "approval.pending",
                    json.dumps({"request_id": "req-manual-old"}),
                    callback_url,
                    "delivered",
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    old_delivered_at,
                    old_delivered_at,
                ),
            ),
        ]
    )

    muted = service.mute_webhook_endpoint(
        WebhookEndpointMuteRequest(callback_url=callback_url, muted_for_seconds=300, reason="operator pause"),
        actor="operator",
    )
    assert muted.callback_url == callback_url
    assert muted.muted_until is not None
    assert muted.mute_reason == "operator pause"

    queued_during_mute = service.list_webhook_events(request_id="req-manual-queued")[0]
    assert parse_iso(queued_during_mute.available_at) >= parse_iso(muted.muted_until)

    pruned = service.prune_webhook_history(emit_audit=True, actor="operator")
    assert pruned.total_deleted == 1

    history = service.list_webhook_prune_history(limit=5)
    assert history[0].actor == "operator"
    assert history[0].total_deleted == 1

    unmuted = service.unmute_webhook_endpoint(
        WebhookEndpointUnmuteRequest(callback_url=callback_url),
        actor="operator",
    )
    assert unmuted.muted_until is None
    assert unmuted.mute_reason is None

    released = service.list_webhook_events(request_id="req-manual-queued")[0]
    assert released.available_at is not None
    assert parse_iso(released.available_at) <= utc_now() + timedelta(seconds=1)


def test_failed_delivery_schedules_automatic_retry_with_backoff(monkeypatch, service):
    tasks = []

    class FailingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            request = httpx.Request("POST", url)
            response = httpx.Response(503, request=request)
            raise httpx.HTTPStatusError("service unavailable", request=request, response=response)

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", FailingClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: tasks.append(task))

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="digest.publish",
            action_hash="sha256:auto-retry",
            risk_level="low",
            callback_url="https://example.com/webhooks",
        )
    )
    assert len(tasks) == 1
    tasks[0]()

    events = service.list_webhook_events(request.id)
    failed_events = [event for event in events if event.status == "failed"]
    queued_events = [event for event in events if event.status == "queued"]
    assert len(failed_events) == 1
    assert len(queued_events) == 1
    retry_event = queued_events[0]
    assert retry_event.retry_parent_id == failed_events[0].id
    assert retry_event.retry_attempt == 1
    assert retry_event.available_at is not None
    retry_delay_seconds = (parse_iso(retry_event.available_at) - utc_now()).total_seconds()
    assert retry_delay_seconds >= service._settings.webhook_auto_retry_base_delay_seconds - 1
    assert (
        retry_delay_seconds
        <= service._settings.webhook_auto_retry_base_delay_seconds + service._settings.webhook_auto_retry_jitter_seconds + 1
    )

    summary = service.get_webhook_delivery_summary()
    assert summary.scheduled_retry_count == 1
    assert summary.redelivery_count == 1
    assert summary.dead_lettered_count == 0


def test_retry_schedule_caps_delay_and_marks_dead_letter_when_budget_exhausted(monkeypatch, service):
    service._settings.webhook_auto_retry_limit = 2
    service._settings.webhook_auto_retry_base_delay_seconds = 30
    service._settings.webhook_auto_retry_max_delay_seconds = 40
    service._settings.webhook_auto_retry_jitter_seconds = 10

    created_at = utc_now().isoformat().replace("+00:00", "Z")
    service._db.execute(
        """
        INSERT INTO webhook_events(
          id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
          lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
          dead_letter_reason, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "whevt-cap-parent",
            "req-cap",
            "approval.pending",
            json.dumps({"request_id": "req-cap"}),
            "https://example.com/webhooks",
            "failed",
            "timed out",
            2,
            None,
            None,
            None,
            None,
            1,
            None,
            None,
            created_at,
            created_at,
        ),
    )
    parent_row = service._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", ("whevt-cap-parent",))
    service._webhooks._maybe_schedule_retry(parent_row)

    queued = service.list_webhook_events("req-cap", status="queued")
    assert len(queued) == 1
    capped_delay_seconds = (parse_iso(queued[0].available_at) - utc_now()).total_seconds()
    assert capped_delay_seconds <= service._settings.webhook_auto_retry_max_delay_seconds + 1
    assert queued[0].retry_attempt == 2
    service._db.execute("DELETE FROM webhook_events WHERE request_id = ?", ("req-cap",))

    service._settings.webhook_auto_retry_limit = 1
    service._settings.webhook_auto_retry_base_delay_seconds = 0
    service._settings.webhook_auto_retry_max_delay_seconds = 0
    service._settings.webhook_auto_retry_jitter_seconds = 0
    tasks = []

    class FailingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            request = httpx.Request("POST", url)
            response = httpx.Response(503, request=request)
            raise httpx.HTTPStatusError("service unavailable", request=request, response=response)

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", FailingClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: tasks.append(task))

    request = service.create_approval_request(
        CreateApprovalRequest(
            action_type="digest.publish",
            action_hash="sha256:dead-letter",
            risk_level="low",
            callback_url="https://example.com/webhooks",
        )
    )
    assert len(tasks) == 1
    tasks[0]()
    assert len(tasks) == 2
    tasks[1]()

    events = service.list_webhook_events(request.id)
    dead_lettered = [event for event in events if event.dead_lettered_at]
    assert len(dead_lettered) == 1
    assert dead_lettered[0].status == "failed"
    assert "retry budget exhausted" in dead_lettered[0].dead_letter_reason

    summary = service.get_webhook_delivery_summary()
    assert summary.scheduled_retry_count == 0
    assert summary.dead_lettered_count == 1
    assert any("dead-lettered" in alert for alert in summary.alerts)


def test_prune_webhook_history_removes_old_settled_events_but_keeps_active_rows(service):
    now = utc_now()
    old_delivered_at = (now - timedelta(days=20)).isoformat().replace("+00:00", "Z")
    old_retry_at = (now - timedelta(days=40)).isoformat().replace("+00:00", "Z")
    recent_at = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    old_queued_at = (now - timedelta(days=40)).isoformat().replace("+00:00", "Z")
    service._db.execute_many(
        [
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-prune-delivered",
                    "req-prune-delivered",
                    "approval.pending",
                    json.dumps({"request_id": "req-prune-delivered"}),
                    "https://example.com/webhooks/prune",
                    "delivered",
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    old_delivered_at,
                    old_delivered_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-prune-skipped",
                    "req-prune-skipped",
                    "approval.pending",
                    json.dumps({"request_id": "req-prune-skipped"}),
                    "https://example.com/webhooks/prune",
                    "skipped",
                    None,
                    0,
                    None,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    old_delivered_at,
                    old_delivered_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-prune-root",
                    "req-prune-chain",
                    "approval.pending",
                    json.dumps({"request_id": "req-prune-chain"}),
                    "https://example.com/webhooks/prune",
                    "failed",
                    "timed out",
                    2,
                    None,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    old_retry_at,
                    old_retry_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-prune-child",
                    "req-prune-chain",
                    "approval.pending",
                    json.dumps({"request_id": "req-prune-chain"}),
                    "https://example.com/webhooks/prune",
                    "delivered",
                    None,
                    1,
                    None,
                    None,
                    None,
                    "whevt-prune-root",
                    1,
                    None,
                    None,
                    old_retry_at,
                    old_retry_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-prune-recent",
                    "req-prune-recent",
                    "approval.pending",
                    json.dumps({"request_id": "req-prune-recent"}),
                    "https://example.com/webhooks/prune",
                    "delivered",
                    None,
                    1,
                    None,
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    recent_at,
                    recent_at,
                ),
            ),
            (
                """
                INSERT INTO webhook_events(
                  id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
                  lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
                  dead_letter_reason, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "whevt-prune-queued",
                    "req-prune-queued",
                    "approval.pending",
                    json.dumps({"request_id": "req-prune-queued"}),
                    "https://example.com/webhooks/prune",
                    "queued",
                    None,
                    0,
                    None,
                    None,
                    old_queued_at,
                    None,
                    0,
                    None,
                    None,
                    old_queued_at,
                    old_queued_at,
                ),
            ),
        ]
    )

    result = service.prune_webhook_history()
    assert result.deleted_delivered_or_skipped == 2
    assert result.deleted_retry_history_events == 2
    assert result.total_deleted == 4

    remaining_ids = {event.id for event in service.list_webhook_events(limit=50)}
    assert "whevt-prune-delivered" not in remaining_ids
    assert "whevt-prune-skipped" not in remaining_ids
    assert "whevt-prune-root" not in remaining_ids
    assert "whevt-prune-child" not in remaining_ids
    assert "whevt-prune-recent" in remaining_ids
    assert "whevt-prune-queued" in remaining_ids


def test_webhook_delivery_lease_prevents_duplicate_multi_instance_delivery(monkeypatch, settings):
    db = Database(settings.db_path)
    db.ensure_ready()
    now = utc_now().isoformat().replace("+00:00", "Z")
    db.execute(
        """
        INSERT INTO webhook_events(
          id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count, lease_owner, lease_expires_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "whevt-shared",
            "req-shared",
            "approval.pending",
            json.dumps({"request_id": "req-shared"}),
            "https://example.com/webhooks",
            "queued",
            None,
            0,
            None,
            None,
            now,
            now,
        ),
    )

    dispatcher_a = WebhookDispatcher(db, settings)
    dispatcher_b = WebhookDispatcher(db, replace(settings, instance_id="test-instance-b"))
    tasks = []
    calls = {"count": 0}

    class RecordingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            calls["count"] += 1
            return httpx.Response(204, request=httpx.Request("POST", url))

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", RecordingClient)
    monkeypatch.setattr(dispatcher_a, "_launch_delivery_task", lambda task: tasks.append(task))
    monkeypatch.setattr(dispatcher_b, "_launch_delivery_task", lambda task: tasks.append(task))

    assert dispatcher_a.recover_queued_events() == 1
    assert dispatcher_b.recover_queued_events() == 1
    assert len(tasks) == 2

    tasks[0]()
    tasks[1]()

    row = db.fetchone("SELECT * FROM webhook_events WHERE id = ?", ("whevt-shared",))
    assert calls["count"] == 1
    assert row["status"] == "delivered"
    assert row["attempt_count"] == 1
    assert row["lease_owner"] is None
    assert row["lease_expires_at"] is None


def test_retry_webhook_event_now_requeues_stalled_event(monkeypatch, service):
    created_at = (utc_now() - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    available_at = (utc_now() - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    service._db.execute(
        """
        INSERT INTO webhook_events(
          id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
          lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "whevt-stalled",
            "req-stalled",
            "approval.pending",
            json.dumps({"request_id": "req-stalled"}),
            "https://example.com/webhooks",
            "queued",
            None,
            0,
            None,
            None,
            available_at,
            None,
            0,
            created_at,
            created_at,
        ),
    )

    class RecordingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            return httpx.Response(204, request=httpx.Request("POST", url))

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", RecordingClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: task())

    retried = service.retry_webhook_event_now("whevt-stalled")
    assert retried.id == "whevt-stalled"
    assert retried.status == "queued"

    delivered = service.list_webhook_events("req-stalled")
    assert delivered[0].status == "delivered"
    assert retried.available_at is not None

    summary = service.get_webhook_delivery_summary()
    assert summary.backlog_count == 0
    assert summary.stalled_backlog_count == 0
    assert summary.health_state == "healthy"


def test_recover_queued_webhook_reclaims_expired_lease(monkeypatch, service):
    expired_at = (utc_now() - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    created_at = (utc_now() - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    service._db.execute(
        """
        INSERT INTO webhook_events(
          id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count, lease_owner, lease_expires_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "whevt-expired-lease",
            "req-expired-lease",
            "approval.pending",
            json.dumps({"request_id": "req-expired-lease"}),
            "https://example.com/webhooks",
            "queued",
            None,
            0,
            "dead-instance",
            expired_at,
            created_at,
            created_at,
        ),
    )

    class RecordingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            return httpx.Response(204, request=httpx.Request("POST", url))

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", RecordingClient)
    monkeypatch.setattr(service._webhooks, "_launch_delivery_task", lambda task: task())

    assert service.recover_queued_webhook_events() == 1
    event = service.list_webhook_events("req-expired-lease")[0]
    assert event.status == "delivered"
    row = service._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", ("whevt-expired-lease",))
    assert row["lease_owner"] is None
    assert row["lease_expires_at"] is None


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
