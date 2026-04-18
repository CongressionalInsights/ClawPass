"""Reference Scotty adapter for ClawPass.

This adapter submits a sensitive Scotty action to ClawPass and checks final approval state
before executing the downstream side effect.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from clawpass_sdk_py import ClawPassClient


@dataclass(slots=True)
class SensitiveAction:
    action_type: str
    action_ref: str
    payload: dict


def action_hash(payload: dict) -> str:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


class ScottyClawPassAdapter:
    def __init__(self, clawpass_url: str, *, api_key: str) -> None:
        self.client = ClawPassClient(clawpass_url, api_key=api_key)

    def submit_for_approval(self, action: SensitiveAction, requester_id: str, callback_url: str | None = None) -> dict:
        return self.client.create_gated_action(
            action_type=action.action_type,
            action_ref=action.action_ref,
            action_hash=action_hash(action.payload),
            risk_level="high",
            requester_id=requester_id,
            metadata={"producer": "scotty", "payload": action.payload},
            callback_url=callback_url,
        )

    def wait_until_final(self, request_id: str, timeout_seconds: int = 600) -> dict:
        return self.client.wait_for_final_decision(request_id, timeout_seconds=timeout_seconds)

    def require_approved(self, request_id: str, *, action_hash_value: str, producer_id: str) -> dict:
        current = self.client.get_approval_request(request_id)
        return self.client.verify_approved_request(
            current,
            request_id=request_id,
            action_hash=action_hash_value,
            producer_id=producer_id,
        )
