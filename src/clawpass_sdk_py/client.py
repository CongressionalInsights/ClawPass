from __future__ import annotations

from typing import Any

import httpx


class ClawPassClient:
    def __init__(self, base_url: str, *, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self._base_url, timeout=timeout)

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
