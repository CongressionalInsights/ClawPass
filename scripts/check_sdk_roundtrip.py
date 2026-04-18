#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from clawpass_sdk_py import ClawPassClient
from clawpass_server.adapters.ethereum_adapter import EthereumAdapter
from clawpass_server.adapters.webauthn_adapter import WebAuthnAdapter
from clawpass_server.app import create_app
from clawpass_server.core.config import Settings
from clawpass_server.core.database import Database
from clawpass_server.core.service import ClawPassService


class _TestClientAdapter:
    def __init__(self, client: TestClient, headers: dict[str, str] | None = None) -> None:
        self._client = client
        self._headers = headers or {}

    def post(self, path: str, json: dict):
        return self._client.post(path, json=json, headers=self._headers)

    def get(self, path: str, params: dict | None = None):
        return self._client.get(path, params=params, headers=self._headers)

    def close(self) -> None:
        self._client.close()


def _settings(db_path: Path) -> Settings:
    return Settings(
        db_path=db_path,
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
        instance_id="sdk-roundtrip",
        session_secret="sdk-roundtrip-session",
        session_secret_configured=True,
        bootstrap_token="sdk-roundtrip-bootstrap",
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


def _issue_producer_api_key(settings: Settings) -> str:
    db = Database(settings.db_path)
    db.ensure_ready()
    service = ClawPassService(
        settings=settings,
        db=db,
        webauthn=WebAuthnAdapter(settings),
        ethereum=EthereumAdapter(),
    )
    producer = service.create_producer(
        payload=type("ProducerPayload", (), {"name": "sdk-roundtrip", "description": "sdk roundtrip"})()
    )
    key = service.issue_producer_key(
        producer.id,
        payload=type("ProducerKeyPayload", (), {"label": "primary"})(),
    )
    return key.api_key


def main() -> int:
    with TemporaryDirectory() as tmpdir:
        settings = _settings(Path(tmpdir) / "clawpass.db")
        api_key = _issue_producer_api_key(settings)
        app = create_app(settings)
        test_client = TestClient(app)
        client = ClawPassClient("http://testserver", api_key=api_key)
        client._client = _TestClientAdapter(test_client, headers=dict(client._client.headers))
        try:
            created = client.create_gated_action(
                request_id="sdk-roundtrip",
                action_type="sdk.roundtrip",
                action_hash="sha256:sdk-roundtrip",
                risk_level="low",
                requester_id="sdk-benchmark",
            )
            if (
                created["id"] != "sdk-roundtrip"
                or created["status"] != "PENDING"
                or not created.get("producer_id")
                or not created.get("approval_url")
            ):
                raise RuntimeError(f"Unexpected create response: {created}")

            pending = client.list_approval_requests(status="pending")
            if created["id"] not in {request["id"] for request in pending}:
                raise RuntimeError(f"Created request missing from pending list: {pending}")

            cancelled = client.cancel_approval_request(created["id"], reason="sdk roundtrip cleanup")
            if cancelled["id"] != created["id"] or cancelled["status"] != "CANCELLED":
                raise RuntimeError(f"Unexpected cancel response: {cancelled}")

            terminal = client.wait_for_final_decision(created["id"], timeout_seconds=1, poll_interval_seconds=0)
            if terminal["id"] != created["id"] or terminal["status"] != "CANCELLED":
                raise RuntimeError(f"Unexpected terminal response: {terminal}")
        finally:
            client.close()
    print("sdk roundtrip ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
