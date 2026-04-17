from __future__ import annotations

import hashlib
import hmac
import threading
from typing import Any

import httpx

from clawpass_server.core.config import Settings
from clawpass_server.core.constants import (
    WEBHOOK_STATUS_DELIVERED,
    WEBHOOK_STATUS_FAILED,
    WEBHOOK_STATUS_QUEUED,
    WEBHOOK_STATUS_SKIPPED,
)
from clawpass_server.core.database import Database
from clawpass_server.core.schemas import WebhookEventResponse
from clawpass_server.core.utils import json_dumps, stable_id, utc_now_iso

MAX_WEBHOOK_DELIVERY_ATTEMPTS = 2
RETRYABLE_HTTP_STATUS_CODES = {408, 429, 500, 502, 503, 504}


class WebhookDispatcher:
    def __init__(self, db: Database, settings: Settings) -> None:
        self._db = db
        self._settings = settings

    def dispatch(self, *, request_id: str, event_type: str, payload: dict[str, Any], callback_url: str | None) -> WebhookEventResponse:
        now = utc_now_iso()
        event_id = stable_id("whevt")
        payload_json = json_dumps(payload)
        status = WEBHOOK_STATUS_SKIPPED
        error: str | None = None
        attempts = 0

        if callback_url:
            status = WEBHOOK_STATUS_QUEUED

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
        row = self._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", (event_id,))
        if callback_url:
            self._launch_delivery_task(
                lambda: self._deliver_event(
                    event_id=event_id,
                    event_type=event_type,
                    payload_json=payload_json,
                    callback_url=callback_url,
                )
            )
        return WebhookEventResponse(**row)

    def _launch_delivery_task(self, task) -> None:
        thread = threading.Thread(target=task, daemon=True, name="clawpass-webhook-delivery")
        thread.start()

    def _delivery_headers(self, *, event_type: str, payload_json: str) -> dict[str, str]:
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
        return headers

    def _deliver_event(self, *, event_id: str, event_type: str, payload_json: str, callback_url: str) -> None:
        status = WEBHOOK_STATUS_FAILED
        error: str | None = None
        attempts = 0
        headers = self._delivery_headers(event_type=event_type, payload_json=payload_json)

        with httpx.Client(timeout=self._settings.webhook_timeout_seconds) as client:
            for attempt in range(1, MAX_WEBHOOK_DELIVERY_ATTEMPTS + 1):
                attempts = attempt
                try:
                    response = client.post(callback_url, content=payload_json, headers=headers)
                    response.raise_for_status()
                    status = WEBHOOK_STATUS_DELIVERED
                    error = None
                    break
                except Exception as exc:  # pragma: no cover - exercised in integration tests with monkeypatch
                    status = WEBHOOK_STATUS_FAILED
                    error = str(exc)
                    if not self._should_retry(exc) or attempt == MAX_WEBHOOK_DELIVERY_ATTEMPTS:
                        break

        self._db.execute(
            "UPDATE webhook_events SET status = ?, last_error = ?, attempt_count = ?, updated_at = ? WHERE id = ?",
            (status, error, attempts, utc_now_iso(), event_id),
        )

    def _should_retry(self, exc: Exception) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in RETRYABLE_HTTP_STATUS_CODES
        return isinstance(exc, httpx.TransportError)
