from __future__ import annotations

import hashlib
import json

from fastapi import FastAPI, HTTPException

from clawpass_sdk_py import ClawPassClient

app = FastAPI(title="ClawPass Generic Producer Example")
clawpass = ClawPassClient("http://localhost:8081")


def digest(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


@app.post("/send-sensitive")
def send_sensitive(payload: dict) -> dict:
    request = clawpass.create_approval_request(
        action_type="generic.send_sensitive",
        action_ref=payload.get("id"),
        action_hash=digest(payload),
        risk_level="high",
        requester_id="generic-producer",
        metadata={"payload": payload},
    )
    return {
        "message": "Approval request created. Wait for approved callback or poll status.",
        "request_id": request["id"],
        "status": request["status"],
    }


@app.post("/webhooks/clawpass")
def clawpass_webhook(payload: dict) -> dict:
    status = payload.get("status")
    if status != "APPROVED":
        return {"ignored": True, "status": status}

    # Security check: downstream action should verify action_hash/action_ref binding before execution.
    action_hash = payload.get("action_hash")
    if not action_hash:
        raise HTTPException(status_code=400, detail="Missing action hash")
    return {"executed": True, "request_id": payload.get("request_id")}
