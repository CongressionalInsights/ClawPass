from __future__ import annotations

import hashlib
import json
import os

from fastapi import FastAPI, HTTPException

from clawpass_sdk_py import ClawPassClient

app = FastAPI(title="ClawPass Generic Producer Example")
clawpass = ClawPassClient(
    os.environ.get("CLAWPASS_URL", "http://localhost:8081"),
    api_key=os.environ["CLAWPASS_API_KEY"],
)


def digest(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


@app.post("/send-sensitive")
def send_sensitive(payload: dict) -> dict:
    request = clawpass.create_gated_action(
        action_type="generic.send_sensitive",
        action_ref=payload.get("id"),
        action_hash=digest(payload),
        risk_level="high",
        requester_id="generic-producer",
        metadata={"payload": payload},
    )
    return {
        "message": "Approval request created. Hold execution until ClawPass returns a terminal decision.",
        "request_id": request["id"],
        "status": request["status"],
        "approval_url": request["approval_url"],
    }


@app.post("/webhooks/clawpass")
def clawpass_webhook(payload: dict) -> dict:
    status = payload.get("status")
    if status != "APPROVED":
        return {"ignored": True, "status": status}

    request_id = payload.get("request_id")
    if not request_id:
        raise HTTPException(status_code=400, detail="Missing request_id")

    current = clawpass.get_approval_request(request_id)
    clawpass.verify_approved_request(
        current,
        request_id=request_id,
        action_hash=payload.get("action_hash"),
        producer_id=payload.get("producer_id"),
    )
    return {"executed": True, "request_id": request_id}
