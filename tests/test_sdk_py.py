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
            return _DummyResponse(
                {
                    "id": json["request_id"],
                    "status": "PENDING",
                    "producer_id": "producer-123",
                    "approval_url": f"http://localhost:8081/approve/{json['request_id']}",
                }
            )
        if path == "/v1/webhook-endpoints/mute":
            return _DummyResponse(
                {
                    "callback_url": json["callback_url"],
                    "muted_until": "2026-04-17T00:10:00Z",
                    "mute_reason": json.get("reason"),
                    "consecutive_failure_count": 2,
                }
            )
        if path == "/v1/webhook-endpoints/unmute":
            return _DummyResponse(
                {
                    "callback_url": json["callback_url"],
                    "muted_until": None,
                    "mute_reason": None,
                    "consecutive_failure_count": 2,
                }
            )
        if path == "/v1/webhook-events/prune":
            return _DummyResponse({"deleted_delivered_or_skipped": 1, "deleted_retry_history_events": 2, "total_deleted": 3})
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
                    "dead_lettered_count": 0,
                    "failure_rate": 0.5,
                    "redelivery_count": 1,
                    "health_state": "warning",
                    "alerts": ["failure rate high"],
                }
            )
        if path == "/v1/webhook-endpoints/summary":
            return _DummyResponse(
                [
                    {
                        "callback_url": "https://example.com/webhooks",
                        "muted_until": "2026-04-17T00:10:00Z",
                        "mute_reason": "operator pause",
                        "consecutive_failure_count": 2,
                        "total_events": 3,
                        "queued_count": 1,
                        "stalled_count": 0,
                        "delivered_count": 1,
                        "failed_count": 1,
                        "dead_lettered_count": 1,
                        "attempted_count": 2,
                        "failure_rate": 0.5,
                        "next_attempt_at": "2026-04-17T00:00:00Z",
                        "last_event_at": "2026-04-17T00:00:00Z",
                        "latest_error": "timeout",
                        "health_state": "critical",
                    }
                ]
            )
        if path == "/v1/webhook-events":
            return _DummyResponse(
                [
                    {
                        "id": "whevt-filtered",
                        "request_id": params["request_id"],
                        "event_type": params.get("event_type", "approval.cancelled"),
                        "callback_url": params.get("callback_url"),
                        "status": params.get("status", "skipped"),
                        "available_at": None,
                        "lease_expires_at": None,
                        "retry_parent_id": None,
                        "retry_attempt": 0,
                        "dead_lettered_at": None,
                        "dead_letter_reason": None,
                    }
                ]
            )
        if path == "/v1/webhook-prune-history":
            return _DummyResponse(
                [
                    {
                        "created_at": "2026-04-17T00:00:00Z",
                        "actor": "operator",
                        "deleted_delivered_or_skipped": 1,
                        "deleted_retry_history_events": 2,
                        "total_deleted": 3,
                        "delivered_or_skipped_cutoff": "2026-04-01T00:00:00Z",
                        "retry_history_cutoff": "2026-03-01T00:00:00Z",
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


def test_python_sdk_sets_bearer_auth_header_for_producer_calls(monkeypatch):
    captured: dict[str, object] = {}

    class CapturingClient:
        def __init__(self, *, base_url, timeout, headers=None):
            captured["base_url"] = base_url
            captured["timeout"] = timeout
            captured["headers"] = headers

        def close(self) -> None:
            return None

    monkeypatch.setattr("clawpass_sdk_py.client.httpx.Client", CapturingClient)

    client = ClawPassClient("http://localhost:8081", api_key="cpk_test.secret", timeout=5.0)
    try:
        assert captured == {
            "base_url": "http://localhost:8081",
            "timeout": 5.0,
            "headers": {"Authorization": "Bearer cpk_test.secret"},
        }
    finally:
        client.close()


def test_python_sdk_merges_custom_headers_with_bearer_auth(monkeypatch):
    captured: dict[str, object] = {}

    class CapturingClient:
        def __init__(self, *, base_url, timeout, headers=None):
            captured["base_url"] = base_url
            captured["timeout"] = timeout
            captured["headers"] = headers

        def close(self) -> None:
            return None

    monkeypatch.setattr("clawpass_sdk_py.client.httpx.Client", CapturingClient)

    client = ClawPassClient(
        "http://localhost:8081",
        api_key="cpk_test.secret",
        headers={"Cookie": "clawpass_session=session-token", "X-ClawPass-CSRF": "csrf-token"},
    )
    try:
        assert captured == {
            "base_url": "http://localhost:8081",
            "timeout": 10.0,
            "headers": {
                "Authorization": "Bearer cpk_test.secret",
                "Cookie": "clawpass_session=session-token",
                "X-ClawPass-CSRF": "csrf-token",
            },
        }
    finally:
        client.close()


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
    assert response["producer_id"] == "producer-123"
    assert response["approval_url"] == "http://localhost:8081/approve/req-fixed-id"


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
            callback_url="https://example.com/webhooks",
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
            "callback_url": "https://example.com/webhooks",
            "limit": 25,
            "cursor": "whevt-cursor",
        },
    )
    assert response == [
        {
            "id": "whevt-filtered",
            "request_id": "req-cancel",
            "event_type": "approval.pending",
            "callback_url": "https://example.com/webhooks",
            "status": "failed",
            "available_at": None,
            "lease_expires_at": None,
            "retry_parent_id": None,
            "retry_attempt": 0,
            "dead_lettered_at": None,
            "dead_letter_reason": None,
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
    assert response["dead_lettered_count"] == 0
    assert response["failure_rate"] == 0.5
    assert response["redelivery_count"] == 1


def test_python_sdk_list_webhook_endpoint_summaries_uses_endpoint_summary():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.list_webhook_endpoint_summaries(limit=15)
    finally:
        client.close()

    assert fake_client.calls[0] == ("get", "/v1/webhook-endpoints/summary", {"limit": 15})
    assert response[0]["callback_url"] == "https://example.com/webhooks"
    assert response[0]["health_state"] == "critical"
    assert response[0]["muted_until"] == "2026-04-17T00:10:00Z"


def test_python_sdk_prune_webhook_events_uses_prune_endpoint():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        response = client.prune_webhook_events()
    finally:
        client.close()

    assert fake_client.calls[0] == ("post", "/v1/webhook-events/prune", {})
    assert response["total_deleted"] == 3


def test_python_sdk_mute_unmute_and_prune_history_use_endpoint_ops():
    client = ClawPassClient("http://localhost:8081")
    fake_client = _FakeHttpClient()
    client._client = fake_client
    try:
        muted = client.mute_webhook_endpoint(
            "https://example.com/webhooks",
            muted_for_seconds=300,
            reason="operator pause",
        )
        unmuted = client.unmute_webhook_endpoint("https://example.com/webhooks")
        history = client.get_webhook_prune_history(limit=5)
    finally:
        client.close()

    assert fake_client.calls[0] == (
        "post",
        "/v1/webhook-endpoints/mute",
        {
            "callback_url": "https://example.com/webhooks",
            "muted_for_seconds": 300,
            "reason": "operator pause",
        },
    )
    assert fake_client.calls[1] == (
        "post",
        "/v1/webhook-endpoints/unmute",
        {"callback_url": "https://example.com/webhooks"},
    )
    assert fake_client.calls[2] == ("get", "/v1/webhook-prune-history", {"limit": 5})
    assert muted["muted_until"] == "2026-04-17T00:10:00Z"
    assert unmuted["muted_until"] is None
    assert history[0]["total_deleted"] == 3


def test_python_sdk_wait_for_final_decision_polls_until_terminal():
    client = ClawPassClient("http://localhost:8081")
    responses = iter(
        [
            {"id": "req-terminal", "status": "PENDING"},
            {"id": "req-terminal", "status": "APPROVED", "producer_id": "producer-123", "action_hash": "sha256:approved"},
        ]
    )
    client.get_approval_request = lambda request_id: next(responses)  # type: ignore[method-assign]
    try:
        response = client.wait_for_final_decision("req-terminal", timeout_seconds=1, poll_interval_seconds=0)
    finally:
        client.close()

    assert response["status"] == "APPROVED"
    assert response["id"] == "req-terminal"


def test_python_sdk_verify_approved_request_checks_expected_bindings():
    client = ClawPassClient("http://localhost:8081")
    approved = {
        "id": "req-approved",
        "status": "APPROVED",
        "producer_id": "producer-123",
        "action_hash": "sha256:approved",
    }
    try:
        verified = client.verify_approved_request(
            approved,
            request_id="req-approved",
            action_hash="sha256:approved",
            producer_id="producer-123",
        )
    finally:
        client.close()

    assert verified is approved
