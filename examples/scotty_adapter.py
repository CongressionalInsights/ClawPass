"""Reference Scotty adapter for LedgerClaw.

This adapter submits a sensitive Scotty action to LedgerClaw and checks final approval state
before executing the downstream side effect.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from ledgerclaw_sdk_py import LedgerClawClient


@dataclass(slots=True)
class SensitiveAction:
    action_type: str
    action_ref: str
    payload: dict


def action_hash(payload: dict) -> str:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


class ScottyLedgerClawAdapter:
    def __init__(self, ledgerclaw_url: str) -> None:
        self.client = LedgerClawClient(ledgerclaw_url)

    def submit_for_approval(self, action: SensitiveAction, requester_id: str, callback_url: str | None = None) -> dict:
        return self.client.create_approval_request(
            action_type=action.action_type,
            action_ref=action.action_ref,
            action_hash=action_hash(action.payload),
            risk_level="high",
            requester_id=requester_id,
            metadata={"producer": "scotty", "payload": action.payload},
            callback_url=callback_url,
        )

    def wait_until_final(self, request_id: str, timeout_seconds: int = 600) -> dict:
        start = time.monotonic()
        while True:
            current = self.client.get_approval_request(request_id)
            if current["status"] in {"APPROVED", "DENIED", "EXPIRED", "CANCELLED"}:
                return current
            if time.monotonic() - start > timeout_seconds:
                raise TimeoutError(f"Approval request {request_id} timed out")
            time.sleep(2)
