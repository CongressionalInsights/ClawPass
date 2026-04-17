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
        self.calls: list[tuple[str, str, object | None]] = []

    def post(self, path, json):
        self.calls.append(("post", path, json))
        if path == "/v1/approval-requests":
            return _DummyResponse({"id": json["request_id"], "status": "PENDING"})
        if path.endswith("/cancel"):
            return _DummyResponse({"id": path.split("/")[-2], "status": "CANCELLED", "decision": "CANCELLED"})
        if path.endswith("/redeliver"):
            return _DummyResponse({"id": "whevt-redelivered", "status": "queued"})
        if path.endswith("/retry-now"):
            return _DummyResponse({"id": path.split("/")[-2], "status": "queued"})
        raise AssertionError(f"Unexpected POST {path}")

    def get(self, path, params=None):
        self.calls.append(("get", path, params))
        if path == "/v1/approval-requests":
            return _DummyResponse([{"id": "req-pending", "status": "PENDING"}])
        if path == "/v1/webhook-summary":
            return _DummyResponse(
                {
                    "backlog_count": 1,
                    "leased_backlog_count": 0,
                    "stalled_backlog_count": 1,
                    "scheduled_retry_count": 0,
                    "failure_rate": 0.5,
                    "redelivery_count": 1,
                    "health_state": "warning",
                    "alerts": ["failure rate high"],
                }
            )
        if path == "/v1/webhook-events":
            return _DummyResponse(
                [
                    {
                        "request_id": params["request_id"],
                        "event_type": params.get("event_type", "approval.cancelled"),
                        "status": params.get("status", "skipped"),
                        "available_at": None,
                        "lease_expires_at": None,
                        "retry_parent_id": None,
                        "retry_attempt": 0,
                    }
                ]
            )
        if path.startswith("/v1/approvers/") and path.endswith("/summary"):
            return _DummyResponse({"id": path.split("/")[-2], "email": "approver@example.org", "passkey_count": 1})
        if path.startswith("/v1/approval-requests/"):
            return _DummyResponse({"id": path.split("/")[-1], "status": "PENDING"})
        raise AssertionError(f"Unexpected GET {path}")

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

    assert fake_client.calls[0][0] == "post"
    assert fake_client.calls[0][1] == "/v1/approval-requests"
    assert fake_client.calls[0][2]["request_id"] == "req-fixed-id"
    assert response["id"] == "req-fixed-id"


def test_python_sdk_list_approval_requests_forwards_status_filter():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.list_approval_requests(status="pending")
    finally:
        client.close()

    assert fake_client.calls[0] == ("get", "/v1/approval-requests", {"status": "pending"})
    assert response == [{"id": "req-pending", "status": "PENDING"}]


def test_python_sdk_cancel_approval_request_forwards_reason():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.cancel_approval_request("req-cancel", reason="operator cancelled")
    finally:
        client.close()

    assert fake_client.calls[0] == (
        "post",
        "/v1/approval-requests/req-cancel/cancel",
        {"reason": "operator cancelled"},
    )
    assert response["id"] == "req-cancel"
    assert response["status"] == "CANCELLED"


def test_python_sdk_get_approver_summary_forwards_id():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.get_approver_summary("approver-123")
    finally:
        client.close()

    assert fake_client.calls[0] == ("get", "/v1/approvers/approver-123/summary", None)
    assert response["id"] == "approver-123"
    assert response["email"] == "approver@example.org"


def test_python_sdk_list_webhook_events_forwards_request_filter():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.list_webhook_events(
            request_id="req-cancel",
            status="failed",
            event_type="approval.pending",
            limit=25,
            cursor="whevt-cursor",
        )
    finally:
        client.close()

    assert fake_client.calls[0] == (
        "get",
        "/v1/webhook-events",
        {
            "request_id": "req-cancel",
            "status": "failed",
            "event_type": "approval.pending",
            "limit": 25,
            "cursor": "whevt-cursor",
        },
    )
    assert response == [
        {
            "request_id": "req-cancel",
            "event_type": "approval.pending",
            "status": "failed",
            "available_at": None,
            "lease_expires_at": None,
            "retry_parent_id": None,
            "retry_attempt": 0,
        }
    ]


def test_python_sdk_redeliver_webhook_event_forwards_event_id():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.redeliver_webhook_event("whevt-failed")
    finally:
        client.close()

    assert fake_client.calls[0] == ("post", "/v1/webhook-events/whevt-failed/redeliver", {})
    assert response["id"] == "whevt-redelivered"
    assert response["status"] == "queued"


def test_python_sdk_retry_webhook_event_now_forwards_event_id():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.retry_webhook_event_now("whevt-stalled")
    finally:
        client.close()

    assert fake_client.calls[0] == ("post", "/v1/webhook-events/whevt-stalled/retry-now", {})
    assert response["id"] == "whevt-stalled"
    assert response["status"] == "queued"


def test_python_sdk_get_webhook_summary_uses_summary_endpoint():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.get_webhook_summary()
    finally:
        client.close()

    assert fake_client.calls[0] == ("get", "/v1/webhook-summary", None)
    assert response["backlog_count"] == 1
    assert response["stalled_backlog_count"] == 1
    assert response["scheduled_retry_count"] == 0
    assert response["failure_rate"] == 0.5
    assert response["redelivery_count"] == 1
