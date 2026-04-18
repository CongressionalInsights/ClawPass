from __future__ import annotations

import time
from typing import Any

import httpx


class ClawPassClient:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 10.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        merged_headers = dict(headers or {})
        if api_key is not None:
            merged_headers.setdefault("Authorization", f"Bearer {api_key}")
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=timeout,
            headers=merged_headers or None,
        )

    def close(self) -> None:
        self._client.close()

    def create_approval_request(
        self,
        *,
        request_id: str | None = None,
        action_type: str,
        action_hash: str,
        risk_level: str = "low",
        requester_id: str | None = None,
        action_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
        expires_at: str | None = None,
        callback_url: str | None = None,
    ) -> dict[str, Any]:
        response = self._client.post(
            "/v1/approval-requests",
            json={
                "request_id": request_id,
                "action_type": action_type,
                "action_hash": action_hash,
                "risk_level": risk_level,
                "requester_id": requester_id,
                "action_ref": action_ref,
                "metadata": metadata or {},
                "expires_at": expires_at,
                "callback_url": callback_url,
            },
        )
        response.raise_for_status()
        return response.json()

    def create_gated_action(self, **payload: Any) -> dict[str, Any]:
        return self.create_approval_request(**payload)

    def get_approval_request(self, request_id: str) -> dict[str, Any]:
        response = self._client.get(f"/v1/approval-requests/{request_id}")
        response.raise_for_status()
        return response.json()

    def list_approval_requests(self, *, status: str | None = None) -> list[dict[str, Any]]:
        params = {"status": status} if status is not None else None
        response = self._client.get("/v1/approval-requests", params=params)
        response.raise_for_status()
        return response.json()

    def cancel_approval_request(self, request_id: str, *, reason: str | None = None) -> dict[str, Any]:
        response = self._client.post(
            f"/v1/approval-requests/{request_id}/cancel",
            json={"reason": reason},
        )
        response.raise_for_status()
        return response.json()

    def get_approver_summary(self, approver_id: str) -> dict[str, Any]:
        response = self._client.get(f"/v1/approvers/{approver_id}/summary")
        response.raise_for_status()
        return response.json()

    def list_webhook_events(
        self,
        *,
        request_id: str | None = None,
        status: str | None = None,
        event_type: str | None = None,
        callback_url: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> list[dict[str, Any]]:
        params = {
            key: value
            for key, value in {
                "request_id": request_id,
                "status": status,
                "event_type": event_type,
                "callback_url": callback_url,
                "limit": limit,
                "cursor": cursor,
            }.items()
            if value is not None
        } or None
        response = self._client.get("/v1/webhook-events", params=params)
        response.raise_for_status()
        return response.json()

    def get_webhook_summary(self) -> dict[str, Any]:
        response = self._client.get("/v1/webhook-summary")
        response.raise_for_status()
        return response.json()

    def list_webhook_endpoint_summaries(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        params = {"limit": limit} if limit is not None else None
        response = self._client.get("/v1/webhook-endpoints/summary", params=params)
        response.raise_for_status()
        return response.json()

    def mute_webhook_endpoint(
        self,
        callback_url: str,
        *,
        muted_for_seconds: int | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        response = self._client.post(
            "/v1/webhook-endpoints/mute",
            json={
                "callback_url": callback_url,
                "muted_for_seconds": muted_for_seconds,
                "reason": reason,
            },
        )
        response.raise_for_status()
        return response.json()

    def unmute_webhook_endpoint(self, callback_url: str) -> dict[str, Any]:
        response = self._client.post(
            "/v1/webhook-endpoints/unmute",
            json={"callback_url": callback_url},
        )
        response.raise_for_status()
        return response.json()

    def prune_webhook_events(self) -> dict[str, Any]:
        response = self._client.post("/v1/webhook-events/prune", json={})
        response.raise_for_status()
        return response.json()

    def get_webhook_prune_history(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        params = {"limit": limit} if limit is not None else None
        response = self._client.get("/v1/webhook-prune-history", params=params)
        response.raise_for_status()
        return response.json()

    def redeliver_webhook_event(self, event_id: str) -> dict[str, Any]:
        response = self._client.post(f"/v1/webhook-events/{event_id}/redeliver", json={})
        response.raise_for_status()
        return response.json()

    def retry_webhook_event_now(self, event_id: str) -> dict[str, Any]:
        response = self._client.post(f"/v1/webhook-events/{event_id}/retry-now", json={})
        response.raise_for_status()
        return response.json()

    def start_webauthn_registration(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post("/v1/webauthn/register/start", json=payload)
        response.raise_for_status()
        return response.json()

    def complete_webauthn_registration(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post("/v1/webauthn/register/complete", json=payload)
        response.raise_for_status()
        return response.json()

    def start_decision(self, request_id: str, *, approver_id: str, decision: str, method: str) -> dict[str, Any]:
        response = self._client.post(
            f"/v1/approval-requests/{request_id}/decision/start",
            json={"approver_id": approver_id, "decision": decision, "method": method},
        )
        response.raise_for_status()
        return response.json()

    def complete_decision(self, request_id: str, *, challenge_id: str, proof: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(
            f"/v1/approval-requests/{request_id}/decision/complete",
            json={"challenge_id": challenge_id, "proof": proof},
        )
        response.raise_for_status()
        return response.json()

    def wait_for_final_decision(
        self,
        request_id: str,
        *,
        timeout_seconds: float = 600,
        poll_interval_seconds: float = 2,
    ) -> dict[str, Any]:
        started = time.monotonic()
        while True:
            current = self.get_approval_request(request_id)
            if current.get("status") in {"APPROVED", "DENIED", "EXPIRED", "CANCELLED"}:
                return current
            if time.monotonic() - started > timeout_seconds:
                raise TimeoutError(f"Approval request {request_id} did not reach a terminal state in time.")
            time.sleep(poll_interval_seconds)

    def verify_approved_request(
        self,
        request: dict[str, Any],
        *,
        request_id: str | None = None,
        action_hash: str | None = None,
        producer_id: str | None = None,
    ) -> dict[str, Any]:
        if request.get("status") != "APPROVED":
            raise ValueError(f"Approval request is not approved: {request.get('status')}")
        if request_id is not None and request.get("id") != request_id:
            raise ValueError("Approval request id does not match the expected request_id.")
        if action_hash is not None and request.get("action_hash") != action_hash:
            raise ValueError("Approval request action_hash does not match the expected action hash.")
        if producer_id is not None and request.get("producer_id") != producer_id:
            raise ValueError("Approval request producer_id does not match the expected producer identity.")
        return request
