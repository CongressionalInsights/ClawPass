from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ledgerclaw_server.app import create_app
from ledgerclaw_server.core.config import Settings


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "api.db",
        host="127.0.0.1",
        port=8081,
        rp_id="localhost",
        rp_name="LedgerClaw",
        expected_origin="http://localhost:8081",
        expected_origins=["http://localhost:8081"],
        webauthn_timeout_ms=60000,
        challenge_ttl_minutes=10,
        approval_default_ttl_minutes=30,
        webhook_timeout_seconds=1,
        webhook_secret=None,
    )


def test_api_flow_with_mocked_webauthn(monkeypatch, tmp_path: Path):
    from ledgerclaw_server.adapters import webauthn_adapter

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
    assert "LedgerClaw" in root.text

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
