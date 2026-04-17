from __future__ import annotations

import hashlib
import hmac
from typing import Any

import httpx

from clawpass_server.core.config import Settings
from clawpass_server.core.database import Database
from clawpass_server.core.utils import json_dumps, stable_id, utc_now_iso

MAX_WEBHOOK_DELIVERY_ATTEMPTS = 2
RETRYABLE_HTTP_STATUS_CODES = {408, 429, 500, 502, 503, 504}


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
            with httpx.Client(timeout=self._settings.webhook_timeout_seconds) as client:
                for attempt in range(1, MAX_WEBHOOK_DELIVERY_ATTEMPTS + 1):
                    attempts = attempt
                    try:
                        response = client.post(callback_url, content=payload_json, headers=headers)
                        response.raise_for_status()
                        status = "delivered"
                        error = None
                        break
                    except Exception as exc:  # pragma: no cover - exercised in integration tests with monkeypatch
                        status = "failed"
                        error = str(exc)
                        if not self._should_retry(exc) or attempt == MAX_WEBHOOK_DELIVERY_ATTEMPTS:
                            break

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

    def _should_retry(self, exc: Exception) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in RETRYABLE_HTTP_STATUS_CODES
        return isinstance(exc, httpx.TransportError)
