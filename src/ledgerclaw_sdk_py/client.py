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


LedgerClawClient = ClawPassClient
