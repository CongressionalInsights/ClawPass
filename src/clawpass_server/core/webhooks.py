from __future__ import annotations

import hashlib
import hmac
from typing import Any

import httpx

from clawpass_server.core.config import Settings
from clawpass_server.core.database import Database
from clawpass_server.core.utils import json_dumps, stable_id, utc_now_iso


class WebhookDispatcher:
    def __init__(self, db: Database, settings: Settings) -> None:
        self._db = db
        self._settings = settings

    def dispatch(self, *, request_id: str, event_type: str, payload: dict[str, Any], callback_url: str | None) -> None:
        now = utc_now_iso()
        event_id = stable_id("whevt")
        payload_json = json_dumps(payload)
        status = "skipped"
        error: str | None = None
        attempts = 0

        if callback_url:
            attempts = 1
            headers = {
                "Content-Type": "application/json",
                "X-ClawPass-Event": event_type,
                "X-LedgerClaw-Event": event_type,
            }
            if self._settings.webhook_secret:
                signature = hmac.new(
                    self._settings.webhook_secret.encode("utf-8"),
                    payload_json.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                headers["X-ClawPass-Signature"] = f"sha256={signature}"
                headers["X-LedgerClaw-Signature"] = f"sha256={signature}"
            try:
                with httpx.Client(timeout=self._settings.webhook_timeout_seconds) as client:
                    response = client.post(callback_url, content=payload_json, headers=headers)
                    response.raise_for_status()
                status = "delivered"
            except Exception as exc:  # pragma: no cover - exercised in integration tests with monkeypatch
                status = "failed"
                error = str(exc)

        self._db.execute(
            """
            INSERT INTO webhook_events(
              id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                request_id,
                event_type,
                payload_json,
                callback_url,
                status,
                error,
                attempts,
                now,
                now,
            ),
        )
