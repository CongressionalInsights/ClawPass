from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
import httpx

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clawpass_server.app import create_app
from clawpass_server.core.config import Settings
from clawpass_server.core.database import Database
from clawpass_server.core.utils import utc_now


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "api.db",
        host="127.0.0.1",
        port=8081,
        rp_id="localhost",
        rp_name="ClawPass",
        expected_origin="http://localhost:8081",
        expected_origins=["http://localhost:8081"],
        webauthn_timeout_ms=60000,
        challenge_ttl_minutes=10,
        approval_default_ttl_minutes=30,
        instance_id="api-test-instance",
        webhook_timeout_seconds=1,
        webhook_delivery_lease_seconds=30,
        webhook_backlog_alert_threshold=1,
        webhook_backlog_alert_after_seconds=30,
        webhook_failure_rate_alert_threshold=0.25,
        webhook_secret=None,
    )


def test_api_flow_with_mocked_webauthn(monkeypatch, tmp_path: Path):
    from clawpass_server.adapters import webauthn_adapter

    class DummyRegistration:
        credential_id = "cred-api"
        credential_public_key = "pub-key"
        sign_count = 0
        aaguid = None

    monkeypatch.setattr(
        webauthn_adapter.WebAuthnAdapter,
        "generate_registration",
        lambda self, **kwargs: ({"challenge": "abc", "user": {"id": "dGVzdA", "name": kwargs["user_name"]}}, "abc"),
    )
    monkeypatch.setattr(
        webauthn_adapter.WebAuthnAdapter,
        "verify_registration",
        lambda self, **kwargs: DummyRegistration(),
    )
    monkeypatch.setattr(
        webauthn_adapter.WebAuthnAdapter,
        "generate_authentication",
        lambda self, **kwargs: ({"challenge": "def", "allowCredentials": [{"id": "cred-api"}]}, "def"),
    )
    monkeypatch.setattr(
        webauthn_adapter.WebAuthnAdapter,
        "verify_authentication",
        lambda self, **kwargs: kwargs["credential_current_sign_count"] + 1,
    )

    client = TestClient(create_app(_settings(tmp_path)))

    root = client.get("/")
    assert root.status_code == 200
    assert "ClawPass" in root.text

    start = client.post(
        "/v1/webauthn/register/start",
        json={"email": "api@example.org", "display_name": "Api User"},
    )
    assert start.status_code == 200
    start_payload = start.json()

    complete = client.post(
        "/v1/webauthn/register/complete",
        json={"session_id": start_payload["session_id"], "credential": {"id": "cred-api"}},
    )
    assert complete.status_code == 200
    approver_id = complete.json()["approver_id"]

    create_request = client.post(
        "/v1/approval-requests",
        json={"action_type": "email.send", "action_hash": "sha256:api", "risk_level": "high"},
    )
    assert create_request.status_code == 200
    req = create_request.json()

    start_decision = client.post(
        f"/v1/approval-requests/{req['id']}/decision/start",
        json={"approver_id": approver_id, "decision": "APPROVE", "method": "webauthn"},
    )
    assert start_decision.status_code == 200
    challenge = start_decision.json()

    done = client.post(
        f"/v1/approval-requests/{req['id']}/decision/complete",
        json={"challenge_id": challenge["challenge_id"], "proof": {"credential": {"id": "cred-api"}}},
    )
    assert done.status_code == 200
    assert done.json()["request"]["status"] == "APPROVED"


def test_list_approval_requests_status_filter_expires_stale_pending_items(tmp_path: Path):
    settings = _settings(tmp_path)
    client = TestClient(create_app(settings))

    active = client.post(
        "/v1/approval-requests",
        json={"action_type": "digest.publish", "action_hash": "sha256:pending", "risk_level": "low"},
    )
    assert active.status_code == 200

    expired = client.post(
        "/v1/approval-requests",
        json={"action_type": "digest.publish", "action_hash": "sha256:expired", "risk_level": "low"},
    )
    assert expired.status_code == 200
    expired_id = expired.json()["id"]

    expired_at = (utc_now() - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    Database(settings.db_path).execute(
        "UPDATE approval_requests SET expires_at = ? WHERE id = ?",
        (expired_at, expired_id),
    )

    pending = client.get("/v1/approval-requests", params={"status": "PENDING"})
    assert pending.status_code == 200
    pending_ids = {request["id"] for request in pending.json()}
    assert active.json()["id"] in pending_ids
    assert expired_id not in pending_ids

    expired_list = client.get("/v1/approval-requests", params={"status": "EXPIRED"})
    assert expired_list.status_code == 200
    expired_ids = {request["id"] for request in expired_list.json()}
    assert expired_id in expired_ids
    assert active.json()["id"] not in expired_ids


def test_cancel_request_emits_cancelled_webhook_event(tmp_path: Path):
    client = TestClient(create_app(_settings(tmp_path)))

    created = client.post(
        "/v1/approval-requests",
        json={"action_type": "digest.publish", "action_hash": "sha256:cancel", "risk_level": "low"},
    )
    assert created.status_code == 200
    request_id = created.json()["id"]

    cancelled = client.post(
        f"/v1/approval-requests/{request_id}/cancel",
        json={"reason": "operator cancelled"},
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "CANCELLED"

    events = client.get("/v1/webhook-events", params={"request_id": request_id})
    assert events.status_code == 200
    event_types = {event["event_type"] for event in events.json()}
    assert "approval.pending" in event_types
    assert "approval.cancelled" in event_types


def test_duplicate_request_id_returns_conflict(tmp_path: Path):
    client = TestClient(create_app(_settings(tmp_path)))
    payload = {
        "request_id": "req-fixed-id",
        "action_type": "digest.publish",
        "action_hash": "sha256:first",
        "risk_level": "low",
    }

    created = client.post("/v1/approval-requests", json=payload)
    assert created.status_code == 200

    duplicate = client.post(
        "/v1/approval-requests",
        json={**payload, "action_hash": "sha256:second"},
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.json()["detail"]


def test_invalid_expires_at_returns_bad_request(tmp_path: Path):
    client = TestClient(create_app(_settings(tmp_path)))

    response = client.post(
        "/v1/approval-requests",
        json={
            "action_type": "digest.publish",
            "action_hash": "sha256:bad-expiry",
            "risk_level": "low",
            "expires_at": "not-a-timestamp",
        },
    )
    assert response.status_code == 400
    assert "valid ISO 8601" in response.json()["detail"]


def test_naive_expires_at_is_treated_as_utc(tmp_path: Path):
    client = TestClient(create_app(_settings(tmp_path)))
    future_naive = (utc_now() + timedelta(minutes=5)).replace(tzinfo=None).isoformat(timespec="seconds")

    response = client.post(
        "/v1/approval-requests",
        json={
            "action_type": "digest.publish",
            "action_hash": "sha256:naive-expiry",
            "risk_level": "low",
            "expires_at": future_naive,
        },
    )
    assert response.status_code == 200
    assert response.json()["expires_at"].endswith("Z")


def test_list_approval_requests_status_filter_is_case_insensitive_and_validated(tmp_path: Path):
    client = TestClient(create_app(_settings(tmp_path)))

    created = client.post(
        "/v1/approval-requests",
        json={"action_type": "digest.publish", "action_hash": "sha256:pending", "risk_level": "low"},
    )
    assert created.status_code == 200
    created_id = created.json()["id"]

    pending = client.get("/v1/approval-requests", params={"status": "pending"})
    assert pending.status_code == 200
    pending_ids = {request["id"] for request in pending.json()}
    assert created_id in pending_ids

    invalid = client.get("/v1/approval-requests", params={"status": "unknown"})
    assert invalid.status_code == 400
    assert "Unsupported status" in invalid.json()["detail"]


def test_webhook_events_support_filters_and_redelivery(monkeypatch, tmp_path: Path):
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
    monkeypatch.setattr("clawpass_server.core.webhooks.WebhookDispatcher._launch_delivery_task", lambda self, task: task())

    client = TestClient(create_app(_settings(tmp_path)))
    created = client.post(
        "/v1/approval-requests",
        json={
            "action_type": "digest.publish",
            "action_hash": "sha256:webhook-api",
            "risk_level": "low",
            "callback_url": "https://example.com/webhooks",
        },
    )
    assert created.status_code == 200
    request_id = created.json()["id"]

    failed = client.get(
        "/v1/webhook-events",
        params={"request_id": request_id, "status": "FAILED", "event_type": "approval.pending"},
    )
    assert failed.status_code == 200
    failed_events = failed.json()
    assert len(failed_events) == 1
    assert failed_events[0]["status"] == "failed"

    redelivered = client.post(f"/v1/webhook-events/{failed_events[0]['id']}/redeliver")
    assert redelivered.status_code == 200
    assert redelivered.json()["id"] != failed_events[0]["id"]
    assert redelivered.json()["status"] == "queued"

    delivered = client.get(
        "/v1/webhook-events",
        params={"request_id": request_id, "status": "delivered", "event_type": "approval.pending"},
    )
    assert delivered.status_code == 200
    delivered_ids = {event["id"] for event in delivered.json()}
    assert redelivered.json()["id"] in delivered_ids


def test_webhook_events_support_limit_and_cursor(tmp_path: Path):
    client = TestClient(create_app(_settings(tmp_path)))

    first = client.post(
        "/v1/approval-requests",
        json={"action_type": "digest.publish", "action_hash": "sha256:first", "risk_level": "low"},
    )
    second = client.post(
        "/v1/approval-requests",
        json={"action_type": "digest.publish", "action_hash": "sha256:second", "risk_level": "low"},
    )
    assert first.status_code == 200
    assert second.status_code == 200

    page_one = client.get("/v1/webhook-events", params={"status": "skipped", "limit": 1})
    assert page_one.status_code == 200
    page_one_payload = page_one.json()
    assert len(page_one_payload) == 1

    page_two = client.get(
        "/v1/webhook-events",
        params={"status": "skipped", "limit": 10, "cursor": page_one_payload[0]["id"]},
    )
    assert page_two.status_code == 200
    page_two_ids = {event["id"] for event in page_two.json()}
    assert page_one_payload[0]["id"] not in page_two_ids


def test_app_startup_recovers_queued_webhooks(monkeypatch, tmp_path: Path):
    settings = _settings(tmp_path)
    captured_headers: list[dict[str, str]] = []

    class RecordingClient:
        def __init__(self, *args, **kwargs):
            return None

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, *, content, headers):
            captured_headers.append(headers)
            return httpx.Response(204, request=httpx.Request("POST", url))

    monkeypatch.setattr("clawpass_server.core.webhooks.httpx.Client", RecordingClient)
    monkeypatch.setattr("clawpass_server.core.webhooks.WebhookDispatcher._launch_delivery_task", lambda self, task: None)

    first_client = TestClient(create_app(settings))
    created = first_client.post(
        "/v1/approval-requests",
        json={
            "action_type": "digest.publish",
            "action_hash": "sha256:recover-startup",
            "risk_level": "low",
            "callback_url": "https://example.com/webhooks",
        },
    )
    assert created.status_code == 200
    request_id = created.json()["id"]

    queued = first_client.get("/v1/webhook-events", params={"request_id": request_id, "status": "queued"})
    assert queued.status_code == 200
    queued_event = queued.json()[0]
    first_client.close()

    monkeypatch.setattr("clawpass_server.core.webhooks.WebhookDispatcher._launch_delivery_task", lambda self, task: task())
    second_client = TestClient(create_app(settings))
    recovered = second_client.get("/v1/webhook-events", params={"request_id": request_id})
    assert recovered.status_code == 200
    recovered_event = recovered.json()[0]
    second_client.close()

    assert recovered_event["status"] == "delivered"
    assert recovered_event["attempt_count"] == 1
    assert captured_headers[0]["X-ClawPass-Webhook-Id"] == queued_event["id"]
    assert captured_headers[0]["X-LedgerClaw-Webhook-Id"] == queued_event["id"]


def test_webhook_summary_reports_failure_rate_and_redelivery_outcomes(monkeypatch, tmp_path: Path):
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
    monkeypatch.setattr("clawpass_server.core.webhooks.WebhookDispatcher._launch_delivery_task", lambda self, task: task())

    client = TestClient(create_app(_settings(tmp_path)))
    created = client.post(
        "/v1/approval-requests",
        json={
            "action_type": "digest.publish",
            "action_hash": "sha256:webhook-summary-api",
            "risk_level": "low",
            "callback_url": "https://example.com/webhooks",
        },
    )
    assert created.status_code == 200
    request_id = created.json()["id"]
    failed_event = client.get(
        "/v1/webhook-events",
        params={"request_id": request_id, "status": "failed", "event_type": "approval.pending"},
    )
    assert failed_event.status_code == 200
    failed_event_id = failed_event.json()[0]["id"]

    redelivered = client.post(f"/v1/webhook-events/{failed_event_id}/redeliver")
    assert redelivered.status_code == 200

    summary = client.get("/v1/webhook-summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["backlog_count"] == 0
    assert payload["leased_backlog_count"] == 0
    assert payload["stalled_backlog_count"] == 0
    assert payload["delivered_count"] == 1
    assert payload["failed_count"] == 1
    assert payload["attempted_count"] == 2
    assert payload["failure_rate"] == 0.5
    assert payload["redelivery_count"] == 1
    assert payload["redelivery_backlog_count"] == 0
    assert payload["redelivery_delivered_count"] == 1
    assert payload["redelivery_failed_count"] == 0
    assert payload["last_event_at"] is not None
    assert payload["health_state"] == "warning"
    assert len(payload["alerts"]) == 1
    assert "failure rate" in payload["alerts"][0]
