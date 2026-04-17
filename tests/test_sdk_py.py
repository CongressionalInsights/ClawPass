from __future__ import annotations

from clawpass_sdk_py.client import ClawPassClient


class _DummyResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


class _FakeHttpClient:
    def __init__(self):
        self.captured: dict[str, object] = {}

    def post(self, path, json):
        self.captured["path"] = path
        self.captured["json"] = json
        return _DummyResponse({"id": json["request_id"], "status": "PENDING"})

    def close(self) -> None:
        return None


def test_python_sdk_create_approval_request_forwards_request_id():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.create_approval_request(
            request_id="req-fixed-id",
            action_type="digest.publish",
            action_hash="sha256:fixed",
            risk_level="low",
        )
    finally:
        client.close()

    assert fake_client.captured["path"] == "/v1/approval-requests"
    assert fake_client.captured["json"]["request_id"] == "req-fixed-id"
    assert response["id"] == "req-fixed-id"
