#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from clawpass_sdk_py import ClawPassClient
from clawpass_server.app import create_app
from clawpass_server.core.config import Settings


class _TestClientAdapter:
    def __init__(self, client: TestClient) -> None:
        self._client = client

    def post(self, path: str, json: dict):
        return self._client.post(path, json=json)

    def get(self, path: str, params: dict | None = None):
        return self._client.get(path, params=params)

    def close(self) -> None:
        self._client.close()


def _settings(db_path: Path) -> Settings:
    return Settings(
        db_path=db_path,
        host="127.0.0.1",
        port=8081,
        rp_id="localhost",
        rp_name="ClawPass",
        expected_origin="http://localhost:8081",
        expected_origins=["http://localhost:8081"],
        webauthn_timeout_ms=60000,
        challenge_ttl_minutes=10,
        approval_default_ttl_minutes=30,
        instance_id="sdk-roundtrip",
        webhook_timeout_seconds=1,
        webhook_delivery_lease_seconds=30,
        webhook_retry_poll_seconds=0,
        webhook_auto_retry_limit=2,
        webhook_auto_retry_base_delay_seconds=30,
        webhook_backlog_alert_threshold=1,
        webhook_backlog_alert_after_seconds=30,
        webhook_failure_rate_alert_threshold=0.25,
        webhook_secret=None,
    )


def main() -> int:
    with TemporaryDirectory() as tmpdir:
        app = create_app(_settings(Path(tmpdir) / "clawpass.db"))
        test_client = TestClient(app)
        client = ClawPassClient("http://testserver")
        client._client = _TestClientAdapter(test_client)
        try:
            created = client.create_approval_request(
                request_id="sdk-roundtrip",
                action_type="sdk.roundtrip",
                action_hash="sha256:sdk-roundtrip",
                risk_level="low",
                requester_id="sdk-benchmark",
            )
            if created["id"] != "sdk-roundtrip" or created["status"] != "PENDING":
                raise RuntimeError(f"Unexpected create response: {created}")

            pending = client.list_approval_requests(status="pending")
            if created["id"] not in {request["id"] for request in pending}:
                raise RuntimeError(f"Created request missing from pending list: {pending}")

            cancelled = client.cancel_approval_request(created["id"], reason="sdk roundtrip cleanup")
            if cancelled["id"] != created["id"] or cancelled["status"] != "CANCELLED":
                raise RuntimeError(f"Unexpected cancel response: {cancelled}")

            events = client.list_webhook_events(
                request_id=created["id"],
                status="skipped",
                event_type="approval.cancelled",
                limit=10,
            )
            if not events or events[0]["event_type"] != "approval.cancelled":
                raise RuntimeError(f"Unexpected webhook events: {events}")

            summary = client.get_webhook_summary()
            if (
                summary["backlog_count"] != 0
                or summary["stalled_backlog_count"] != 0
                or summary["scheduled_retry_count"] != 0
                or summary["redelivery_count"] != 0
                or summary["health_state"] != "healthy"
                or summary["alerts"]
            ):
                raise RuntimeError(f"Unexpected webhook summary: {summary}")

            fetched = client.get_approval_request(created["id"])
            if fetched["id"] != created["id"] or fetched["status"] != "CANCELLED":
                raise RuntimeError(f"Unexpected fetch response: {fetched}")
        finally:
            client.close()
    print("sdk roundtrip ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
