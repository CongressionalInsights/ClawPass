from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

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
        webhook_timeout_seconds=1,
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
