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

    def get(self, path: str):
        return self._client.get(path)

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
        webhook_timeout_seconds=1,
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

            fetched = client.get_approval_request(created["id"])
            if fetched["id"] != created["id"] or fetched["status"] != "PENDING":
                raise RuntimeError(f"Unexpected fetch response: {fetched}")
        finally:
            client.close()
    print("sdk roundtrip ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
