from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clawpass_server.app import create_app
from clawpass_server.core.auth import ADMIN_CSRF_COOKIE
from clawpass_server.core.config import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "api.db",
        host="127.0.0.1",
        port=8081,
        base_url="http://localhost:8081",
        rp_id="localhost",
        rp_name="ClawPass",
        expected_origin="http://localhost:8081",
        expected_origins=["http://localhost:8081"],
        webauthn_timeout_ms=60000,
        challenge_ttl_minutes=10,
        approval_default_ttl_minutes=30,
        admin_session_ttl_minutes=720,
        instance_id="api-test-instance",
        session_secret="test-session-secret",
        session_secret_configured=True,
        bootstrap_token="bootstrap-secret",
        deployment_mode="development",
        webhook_timeout_seconds=1,
        webhook_delivery_lease_seconds=30,
        webhook_retry_poll_seconds=0,
        webhook_auto_retry_limit=2,
        webhook_auto_retry_base_delay_seconds=30,
        webhook_auto_retry_max_delay_seconds=300,
        webhook_auto_retry_jitter_seconds=10,
        webhook_backlog_alert_threshold=1,
        webhook_backlog_alert_after_seconds=30,
        webhook_failure_rate_alert_threshold=0.25,
        webhook_event_retention_days=14,
        webhook_retry_history_retention_days=30,
        webhook_endpoint_auto_mute_threshold=3,
        webhook_endpoint_auto_mute_seconds=600,
        webhook_secret=None,
    )


def _mock_webauthn(monkeypatch) -> None:
    from clawpass_server.adapters import webauthn_adapter

    monkeypatch.setattr(
        webauthn_adapter.WebAuthnAdapter,
        "generate_registration",
        lambda self, **kwargs: (
            {
                "challenge": "reg-challenge",
                "user": {
                    "id": "dGVzdA",
                    "name": kwargs["user_name"],
                    "displayName": kwargs["user_display_name"],
                },
                "rp": {"id": "localhost", "name": "ClawPass"},
                "excludeCredentials": [],
            },
            "reg-challenge",
        ),
    )
    monkeypatch.setattr(
        webauthn_adapter.WebAuthnAdapter,
        "verify_registration",
        lambda self, **kwargs: type(
            "DummyRegistration",
            (),
            {
                "credential_id": kwargs["credential"]["id"],
                "credential_public_key": "pub-key",
                "sign_count": 0,
                "aaguid": None,
            },
        )(),
    )
    monkeypatch.setattr(
        webauthn_adapter.WebAuthnAdapter,
        "generate_authentication",
        lambda self, **kwargs: (
            {
                "challenge": "auth-challenge",
                "allowCredentials": [{"id": credential_id} for credential_id in kwargs["allowed_credential_ids"]],
                "rpId": "localhost",
            },
            "auth-challenge",
        ),
    )
    monkeypatch.setattr(
        webauthn_adapter.WebAuthnAdapter,
        "verify_authentication",
        lambda self, **kwargs: kwargs["credential_current_sign_count"] + 1,
    )


def _csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-ClawPass-CSRF": client.cookies[ADMIN_CSRF_COOKIE]}


def _bootstrap_admin(client: TestClient) -> dict[str, str]:
    start = client.post(
        "/v1/setup/bootstrap/start",
        json={
            "bootstrap_token": "bootstrap-secret",
            "email": "admin@example.org",
            "display_name": "Admin",
        },
    )
    assert start.status_code == 200

    complete = client.post(
        "/v1/setup/bootstrap/complete",
        json={
            "session_id": start.json()["session_id"],
            "credential": {"id": "cred-admin"},
            "label": "Primary passkey",
        },
    )
    assert complete.status_code == 200
    return complete.json()


def _create_producer_key(client: TestClient, *, name: str) -> tuple[dict[str, str], str]:
    producer = client.post(
        "/v1/operator/producers",
        json={"name": name, "description": f"{name} description"},
        headers=_csrf_headers(client),
    )
    assert producer.status_code == 200

    key = client.post(
        f"/v1/operator/producers/{producer.json()['id']}/keys",
        json={"label": f"{name} key"},
        headers=_csrf_headers(client),
    )
    assert key.status_code == 200
    return producer.json(), key.json()["api_key"]


def _create_request(client: TestClient, api_key: str, **overrides) -> dict[str, str]:
    payload = {
        "request_id": "req-1",
        "action_type": "email.send",
        "action_hash": "sha256:abc123",
        "requester_id": "agent-run-1",
        "risk_level": "high",
        "callback_url": "https://example.com/webhooks",
    }
    payload.update(overrides)
    response = client.post(
        "/v1/approval-requests",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert response.status_code == 200
    return response.json()


def _login_as(client: TestClient, *, email: str, credential_id: str) -> dict[str, str]:
    start = client.post("/v1/auth/login/start", json={"email": email})
    assert start.status_code == 200
    complete = client.post(
        "/v1/auth/login/complete",
        json={"session_id": start.json()["session_id"], "credential": {"id": credential_id}},
    )
    assert complete.status_code == 200
    return complete.json()


def test_fresh_install_routes_to_setup_and_reports_bootstrap_status(monkeypatch, tmp_path: Path):
    _mock_webauthn(monkeypatch)
    client = TestClient(create_app(_settings(tmp_path)))

    root = client.get("/", follow_redirects=False)
    assert root.status_code == 302
    assert root.headers["location"] == "/setup"

    setup_status = client.get("/v1/setup/status")
    assert setup_status.status_code == 200
    assert setup_status.json() == {
        "initialized": False,
        "bootstrap_configured": True,
    }


def test_bootstrap_logout_and_passkey_login_flow(monkeypatch, tmp_path: Path):
    _mock_webauthn(monkeypatch)
    client = TestClient(create_app(_settings(tmp_path)))

    bootstrap = _bootstrap_admin(client)
    assert bootstrap["email"] == "admin@example.org"
    assert bootstrap["passkey_count"] == 1

    session = client.get("/v1/admin/session")
    assert session.status_code == 200
    assert session.json()["approver_id"] == bootstrap["approver_id"]

    app_redirect = client.get("/", follow_redirects=False)
    assert app_redirect.status_code == 302
    assert app_redirect.headers["location"] == "/app"

    logout = client.post("/v1/auth/logout")
    assert logout.status_code == 200

    locked = client.get("/app", follow_redirects=False)
    assert locked.status_code == 302
    assert locked.headers["location"] == "/login"

    login_start = client.post("/v1/auth/admin/login/start")
    assert login_start.status_code == 200

    login_complete = client.post(
        "/v1/auth/admin/login/complete",
        json={"session_id": login_start.json()["session_id"], "credential": {"id": "cred-admin"}},
    )
    assert login_complete.status_code == 200
    assert login_complete.json()["email"] == "admin@example.org"


def test_producer_api_keys_gate_request_creation_and_scope_reads(monkeypatch, tmp_path: Path):
    _mock_webauthn(monkeypatch)
    settings = _settings(tmp_path)
    admin_client = TestClient(create_app(settings))
    _bootstrap_admin(admin_client)

    producer_a, api_key_a = _create_producer_key(admin_client, name="producer-a")
    producer_b, api_key_b = _create_producer_key(admin_client, name="producer-b")
    producer_client = TestClient(create_app(settings))

    missing_auth = producer_client.post(
        "/v1/approval-requests",
        json={"action_type": "email.send", "action_hash": "sha256:no-auth", "risk_level": "high"},
    )
    assert missing_auth.status_code == 401

    created = _create_request(producer_client, api_key_a, request_id="req-producer-a")
    assert created["producer_id"] == producer_a["id"]
    assert created["approval_url"].endswith(f"/approve/{created['id']}")

    producer_get = producer_client.get(
        f"/v1/approval-requests/{created['id']}",
        headers={"Authorization": f"Bearer {api_key_a}"},
    )
    assert producer_get.status_code == 200
    assert producer_get.json()["id"] == created["id"]

    cross_producer_get = producer_client.get(
        f"/v1/approval-requests/{created['id']}",
        headers={"Authorization": f"Bearer {api_key_b}"},
    )
    assert cross_producer_get.status_code == 404

    producer_list = producer_client.get(
        "/v1/approval-requests",
        headers={"Authorization": f"Bearer {api_key_a}"},
    )
    assert producer_list.status_code == 200
    assert [item["id"] for item in producer_list.json()] == [created["id"]]

    assert producer_b["id"] != producer_a["id"]


def test_admin_can_approve_producer_request_and_producer_observes_approved_state(monkeypatch, tmp_path: Path):
    _mock_webauthn(monkeypatch)
    settings = _settings(tmp_path)
    admin_client = TestClient(create_app(settings))
    _bootstrap_admin(admin_client)
    producer, api_key = _create_producer_key(admin_client, name="mail-agent")
    producer_client = TestClient(create_app(settings))

    created = _create_request(producer_client, api_key, request_id="req-approve")
    assert created["producer_id"] == producer["id"]

    start = admin_client.post(
        f"/v1/approval-requests/{created['id']}/decision/start",
        json={"decision": "APPROVE", "method": "webauthn"},
        headers=_csrf_headers(admin_client),
    )
    assert start.status_code == 200

    complete = admin_client.post(
        f"/v1/approval-requests/{created['id']}/decision/complete",
        json={"challenge_id": start.json()["challenge_id"], "proof": {"credential": {"id": "cred-admin"}}},
        headers=_csrf_headers(admin_client),
    )
    assert complete.status_code == 200
    assert complete.json()["request"]["status"] == "APPROVED"
    assert complete.json()["request"]["approver_id"] is not None

    producer_view = producer_client.get(
        f"/v1/approval-requests/{created['id']}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert producer_view.status_code == 200
    assert producer_view.json()["status"] == "APPROVED"

    webhook_events = admin_client.get(
        "/v1/webhook-events",
        params={"request_id": created["id"]},
    )
    assert webhook_events.status_code == 200
    event_types = {event["event_type"] for event in webhook_events.json()}
    assert event_types == {"approval.pending", "approval.approved"}


def test_operator_routes_require_admin_session_and_csrf(monkeypatch, tmp_path: Path):
    _mock_webauthn(monkeypatch)
    settings = _settings(tmp_path)
    admin_client = TestClient(create_app(settings))
    _bootstrap_admin(admin_client)
    _, api_key = _create_producer_key(admin_client, name="ops-agent")
    created = _create_request(admin_client, api_key, request_id="req-webhook")

    anonymous_client = TestClient(create_app(settings))

    events = anonymous_client.get("/v1/webhook-events", params={"request_id": created["id"]})
    assert events.status_code == 401

    mute = anonymous_client.post(
        "/v1/webhook-endpoints/mute",
        json={"callback_url": "https://example.com/webhooks", "reason": "pause"},
    )
    assert mute.status_code == 401

    missing_csrf = admin_client.post(
        "/v1/webhook-endpoints/mute",
        json={"callback_url": "https://example.com/webhooks", "reason": "pause"},
    )
    assert missing_csrf.status_code == 403


def test_invited_approver_can_enroll_login_and_approve(monkeypatch, tmp_path: Path):
    _mock_webauthn(monkeypatch)
    settings = _settings(tmp_path)
    admin_client = TestClient(create_app(settings))
    _bootstrap_admin(admin_client)
    producer, api_key = _create_producer_key(admin_client, name="invite-agent")
    producer_client = TestClient(create_app(settings))

    invite = admin_client.post(
        "/v1/operator/approver-invites",
        json={"email": "reviewer@example.org", "display_name": "Reviewer"},
        headers=_csrf_headers(admin_client),
    )
    assert invite.status_code == 200
    token = invite.json()["token"]

    invite_page = producer_client.get(f"/v1/invites/{token}")
    assert invite_page.status_code == 200
    assert invite_page.json()["email"] == "reviewer@example.org"

    start = producer_client.post(f"/v1/invites/{token}/start", json={})
    assert start.status_code == 200
    complete = producer_client.post(
        f"/v1/invites/{token}/complete",
        json={"session_id": start.json()["session_id"], "credential": {"id": "cred-reviewer"}},
    )
    assert complete.status_code == 200
    assert complete.json()["is_admin"] is False
    assert complete.json()["email"] == "reviewer@example.org"

    auth_session = producer_client.get("/v1/auth/session")
    assert auth_session.status_code == 200
    assert auth_session.json()["email"] == "reviewer@example.org"
    assert auth_session.json()["is_admin"] is False

    created = _create_request(producer_client, api_key, request_id="req-invite")
    assert created["producer_id"] == producer["id"]

    approval_link = producer_client.get(f"/v1/approval-links/{created['id']}")
    assert approval_link.status_code == 200
    assert approval_link.json()["approval_url"].endswith(f"/approve/{created['id']}")

    start_decision = producer_client.post(
        f"/v1/approval-requests/{created['id']}/decision/start",
        json={"decision": "APPROVE", "method": "webauthn"},
        headers=_csrf_headers(producer_client),
    )
    assert start_decision.status_code == 200

    complete_decision = producer_client.post(
        f"/v1/approval-requests/{created['id']}/decision/complete",
        json={"challenge_id": start_decision.json()["challenge_id"], "proof": {"credential": {"id": "cred-reviewer"}}},
        headers=_csrf_headers(producer_client),
    )
    assert complete_decision.status_code == 200
    assert complete_decision.json()["request"]["status"] == "APPROVED"

    producer_view = producer_client.get(
        f"/v1/approval-requests/{created['id']}",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert producer_view.status_code == 200
    assert producer_view.json()["status"] == "APPROVED"


def test_generic_login_route_uses_email_scoped_approver_credentials(monkeypatch, tmp_path: Path):
    _mock_webauthn(monkeypatch)
    settings = _settings(tmp_path)
    admin_client = TestClient(create_app(settings))
    _bootstrap_admin(admin_client)

    invite = admin_client.post(
        "/v1/operator/approver-invites",
        json={"email": "auditor@example.org", "display_name": "Auditor"},
        headers=_csrf_headers(admin_client),
    )
    assert invite.status_code == 200
    token = invite.json()["token"]

    enrolled_client = TestClient(create_app(settings))
    start = enrolled_client.post(f"/v1/invites/{token}/start", json={})
    assert start.status_code == 200
    complete = enrolled_client.post(
        f"/v1/invites/{token}/complete",
        json={"session_id": start.json()["session_id"], "credential": {"id": "cred-auditor"}},
    )
    assert complete.status_code == 200

    login_client = TestClient(create_app(settings))
    session = _login_as(login_client, email="auditor@example.org", credential_id="cred-auditor")
    assert session["email"] == "auditor@example.org"
    assert session["is_admin"] is False
