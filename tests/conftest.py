from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from clawpass_server.adapters.ethereum_adapter import EthereumAdapter  # noqa: E402
from clawpass_server.core.config import Settings  # noqa: E402
from clawpass_server.core.database import Database  # noqa: E402
from clawpass_server.core.service import ClawPassService  # noqa: E402


class FakeWebAuthnAdapter:
    def generate_registration(self, **kwargs):
        challenge = "reg-challenge"
        options = {
            "challenge": challenge,
            "user": {"id": "dXNlcg", "name": kwargs["user_name"], "displayName": kwargs["user_display_name"]},
            "excludeCredentials": [],
            "rp": {"id": "localhost", "name": "ClawPass"},
        }
        if kwargs.get("is_ledger"):
            options["hints"] = ["security-key", "hybrid"]
        return options, challenge

    def verify_registration(self, **kwargs):
        class Result:
            credential_id = kwargs["credential"]["id"]
            credential_public_key = "pub-key"
            sign_count = 0
            aaguid = None

        return Result()

    def generate_authentication(self, **kwargs):
        challenge = "auth-challenge"
        options = {
            "challenge": challenge,
            "allowCredentials": [{"id": credential_id, "type": "public-key"} for credential_id in kwargs["allowed_credential_ids"]],
            "rpId": "localhost",
        }
        return options, challenge

    def verify_authentication(self, **kwargs):
        return kwargs["credential_current_sign_count"] + 1


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "clawpass.db",
        host="127.0.0.1",
        port=8081,
        rp_id="localhost",
        rp_name="ClawPass",
        expected_origin="http://localhost:8081",
        expected_origins=["http://localhost:8081"],
        webauthn_timeout_ms=60000,
        challenge_ttl_minutes=10,
        approval_default_ttl_minutes=30,
        instance_id="test-instance",
        webhook_timeout_seconds=1.0,
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


@pytest.fixture()
def service(settings: Settings) -> ClawPassService:
    db = Database(settings.db_path)
    db.ensure_ready()
    return ClawPassService(
        settings=settings,
        db=db,
        webauthn=FakeWebAuthnAdapter(),
        ethereum=EthereumAdapter(),
    )
