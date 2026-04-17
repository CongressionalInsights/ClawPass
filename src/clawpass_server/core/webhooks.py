from __future__ import annotations

import json
import hashlib
import hmac
import threading
import time
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
from clawpass_server.core.utils import add_seconds_iso, json_dumps, parse_iso, stable_id, utc_now, utc_now_iso

MAX_WEBHOOK_DELIVERY_ATTEMPTS = 2
RETRYABLE_HTTP_STATUS_CODES = {408, 429, 500, 502, 503, 504}


class WebhookDispatcher:
    def __init__(self, db: Database, settings: Settings) -> None:
        self._db = db
        self._settings = settings
        self._recovery_loop_started = False
        self._recovery_loop_lock = threading.Lock()

    def dispatch(
        self,
        *,
        request_id: str,
        event_type: str,
        payload: dict[str, Any],
        callback_url: str | None,
        available_at: str | None = None,
        retry_parent_id: str | None = None,
        retry_attempt: int = 0,
    ) -> WebhookEventResponse:
        now = utc_now_iso()
        event_id = stable_id("whevt")
        payload_json = json_dumps(payload)
        status = WEBHOOK_STATUS_SKIPPED
        error: str | None = None
        attempts = 0
        available_at = available_at or now

        if callback_url:
            status = WEBHOOK_STATUS_QUEUED
            muted_until = self._active_muted_until(callback_url)
            if muted_until and parse_iso(available_at) < parse_iso(muted_until):
                available_at = muted_until

        self._db.execute(
            """
            INSERT INTO webhook_events(
              id, request_id, event_type, payload_json, callback_url, status, last_error, attempt_count,
              lease_owner, lease_expires_at, available_at, retry_parent_id, retry_attempt, dead_lettered_at,
              dead_letter_reason, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                None,
                None,
                available_at,
                retry_parent_id,
                retry_attempt,
                None,
                None,
                now,
                now,
            ),
        )
        row = self._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", (event_id,))
        if callback_url and parse_iso(available_at) <= utc_now():
            self._schedule_delivery(
                event_id=event_id,
                event_type=event_type,
                payload_json=payload_json,
                callback_url=callback_url,
            )
        return WebhookEventResponse(**row)

    def recover_queued_events(self) -> int:
        now = utc_now_iso()
        rows = self._db.fetchall(
            """
            SELECT id, event_type, payload_json, callback_url, available_at
            FROM webhook_events
            WHERE status = ? AND callback_url IS NOT NULL
              AND (available_at IS NULL OR available_at <= ?)
              AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
            ORDER BY created_at ASC, id ASC
            """,
            (WEBHOOK_STATUS_QUEUED, now, now),
        )
        for row in rows:
            if self._active_muted_until(row["callback_url"]):
                self.defer_event_until_mute(row["id"])
                continue
            self._schedule_delivery(
                event_id=row["id"],
                event_type=row["event_type"],
                payload_json=row["payload_json"],
                callback_url=row["callback_url"],
            )
        return len(rows)

    def start_recovery_loop(self) -> None:
        if self._settings.webhook_retry_poll_seconds <= 0:
            return
        with self._recovery_loop_lock:
            if self._recovery_loop_started:
                return
            self._recovery_loop_started = True
        thread = threading.Thread(target=self._run_recovery_loop, daemon=True, name="clawpass-webhook-recovery")
        thread.start()

    def _launch_delivery_task(self, task) -> None:
        thread = threading.Thread(target=task, daemon=True, name="clawpass-webhook-delivery")
        thread.start()

    def _schedule_delivery(self, *, event_id: str, event_type: str, payload_json: str, callback_url: str) -> None:
        self._launch_delivery_task(
            lambda: self._deliver_event(
                event_id=event_id,
                event_type=event_type,
                payload_json=payload_json,
                callback_url=callback_url,
            )
        )

    def schedule_existing_event(self, event_id: str) -> WebhookEventResponse | None:
        row = self._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", (event_id,))
        if not row or row["status"] != WEBHOOK_STATUS_QUEUED or not row.get("callback_url"):
            return None
        if self._active_muted_until(row["callback_url"]):
            self.defer_event_until_mute(event_id)
            return WebhookEventResponse(**self._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", (event_id,)))
        snapshot = WebhookEventResponse(**row)
        available_at = row.get("available_at")
        if not available_at or parse_iso(available_at) <= utc_now():
            self._schedule_delivery(
                event_id=row["id"],
                event_type=row["event_type"],
                payload_json=row["payload_json"],
                callback_url=row["callback_url"],
            )
        return snapshot

    def defer_event_until_mute(self, event_id: str) -> WebhookEventResponse | None:
        row = self._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", (event_id,))
        if not row or row["status"] != WEBHOOK_STATUS_QUEUED or not row.get("callback_url"):
            return None
        muted_until = self._active_muted_until(row["callback_url"])
        if not muted_until:
            return WebhookEventResponse(**row)
        available_at = row.get("available_at")
        effective_available_at = muted_until
        if available_at and parse_iso(available_at) > parse_iso(muted_until):
            effective_available_at = available_at
        self._db.execute(
            """
            UPDATE webhook_events
            SET available_at = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
            WHERE id = ?
            """,
            (effective_available_at, utc_now_iso(), event_id),
        )
        return WebhookEventResponse(**self._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", (event_id,)))

    def _delivery_headers(self, *, event_id: str, event_type: str, payload_json: str) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-ClawPass-Webhook-Id": event_id,
            "X-LedgerClaw-Webhook-Id": event_id,
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
        if not self._acquire_delivery_lease(event_id):
            return
        row = self._db.fetchone("SELECT * FROM webhook_events WHERE id = ?", (event_id,))
        if not row:
            return
        if self._active_muted_until(callback_url):
            self.defer_event_until_mute(event_id)
            return
        status = WEBHOOK_STATUS_FAILED
        error: str | None = None
        attempts = 0
        retryable_failure = False
        headers = self._delivery_headers(event_id=event_id, event_type=event_type, payload_json=payload_json)

        with httpx.Client(timeout=self._settings.webhook_timeout_seconds) as client:
            for attempt in range(1, MAX_WEBHOOK_DELIVERY_ATTEMPTS + 1):
                attempts = attempt
                try:
                    response = client.post(callback_url, content=payload_json, headers=headers)
                    response.raise_for_status()
                    status = WEBHOOK_STATUS_DELIVERED
                    error = None
                    retryable_failure = False
                    break
                except Exception as exc:  # pragma: no cover - exercised in integration tests with monkeypatch
                    status = WEBHOOK_STATUS_FAILED
                    error = str(exc)
                    retryable_failure = self._should_retry(exc)
                    if not retryable_failure or attempt == MAX_WEBHOOK_DELIVERY_ATTEMPTS:
                        break

        self._db.execute(
            """
            UPDATE webhook_events
            SET status = ?, last_error = ?, attempt_count = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
            WHERE id = ? AND lease_owner = ?
            """,
            (status, error, attempts, utc_now_iso(), event_id, self._settings.instance_id),
        )
        self._sync_endpoint_control_after_delivery(callback_url=callback_url, status=status)
        if status == WEBHOOK_STATUS_FAILED and retryable_failure:
            self._maybe_schedule_retry(row)

    def _should_retry(self, exc: Exception) -> bool:
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in RETRYABLE_HTTP_STATUS_CODES
        return isinstance(exc, httpx.TransportError)

    def _run_recovery_loop(self) -> None:
        while True:
            time.sleep(self._settings.webhook_retry_poll_seconds)
            try:
                self.recover_queued_events()
            except Exception:
                continue

    def _acquire_delivery_lease(self, event_id: str) -> bool:
        now = utc_now_iso()
        claimed = self._db.execute_rowcount(
            """
            UPDATE webhook_events
            SET lease_owner = ?, lease_expires_at = ?, updated_at = ?
            WHERE id = ?
              AND status = ?
              AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
            """,
            (
                self._settings.instance_id,
                add_seconds_iso(self._settings.webhook_delivery_lease_seconds),
                now,
                event_id,
                WEBHOOK_STATUS_QUEUED,
                now,
            ),
        )
        return claimed == 1

    def _active_muted_until(self, callback_url: str | None) -> str | None:
        if not callback_url:
            return None
        row = self._db.fetchone(
            "SELECT muted_until FROM webhook_endpoint_controls WHERE callback_url = ?",
            (callback_url,),
        )
        if not row or not row.get("muted_until"):
            return None
        if parse_iso(row["muted_until"]) <= utc_now():
            return None
        return row["muted_until"]

    def _sync_endpoint_control_after_delivery(self, *, callback_url: str, status: str) -> None:
        row = self._db.fetchone(
            "SELECT * FROM webhook_endpoint_controls WHERE callback_url = ?",
            (callback_url,),
        )
        consecutive_failure_count = int(row.get("consecutive_failure_count") or 0) if row else 0
        muted_until = row.get("muted_until") if row else None
        mute_reason = row.get("mute_reason") if row else None
        if status == WEBHOOK_STATUS_DELIVERED:
            consecutive_failure_count = 0
        elif status == WEBHOOK_STATUS_FAILED:
            consecutive_failure_count += 1
            if (
                self._settings.webhook_endpoint_auto_mute_threshold > 0
                and self._settings.webhook_endpoint_auto_mute_seconds > 0
                and consecutive_failure_count >= self._settings.webhook_endpoint_auto_mute_threshold
            ):
                auto_muted_until = add_seconds_iso(self._settings.webhook_endpoint_auto_mute_seconds)
                if not muted_until or parse_iso(muted_until) <= utc_now() or parse_iso(auto_muted_until) > parse_iso(muted_until):
                    muted_until = auto_muted_until
                    mute_reason = (
                        f"Automatically muted after {consecutive_failure_count} consecutive delivery failures."
                    )
        self._db.execute(
            """
            INSERT INTO webhook_endpoint_controls(
              callback_url, muted_until, mute_reason, consecutive_failure_count, updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(callback_url) DO UPDATE SET
              muted_until = excluded.muted_until,
              mute_reason = excluded.mute_reason,
              consecutive_failure_count = excluded.consecutive_failure_count,
              updated_at = excluded.updated_at
            """,
            (callback_url, muted_until, mute_reason, consecutive_failure_count, utc_now_iso()),
        )

    def _maybe_schedule_retry(self, row: dict[str, Any]) -> None:
        current_retry_attempt = int(row.get("retry_attempt") or 0)
        if current_retry_attempt >= self._settings.webhook_auto_retry_limit:
            self._mark_dead_letter(
                event_id=row["id"],
                reason=f"Automatic retry budget exhausted after {current_retry_attempt} queued retr{'y' if current_retry_attempt == 1 else 'ies'}.",
            )
            return
        next_retry_attempt = current_retry_attempt + 1
        delay_seconds = self._compute_retry_delay_seconds(row["id"], current_retry_attempt)
        self.dispatch(
            request_id=row["request_id"],
            event_type=row["event_type"],
            payload=json.loads(row["payload_json"]),
            callback_url=row["callback_url"],
            available_at=add_seconds_iso(delay_seconds),
            retry_parent_id=row["id"],
            retry_attempt=next_retry_attempt,
        )

    def _compute_retry_delay_seconds(self, event_id: str, current_retry_attempt: int) -> int:
        base_delay = self._settings.webhook_auto_retry_base_delay_seconds * (2 ** max(0, current_retry_attempt))
        capped_delay = min(base_delay, self._settings.webhook_auto_retry_max_delay_seconds)
        jitter_limit = min(
            max(0, self._settings.webhook_auto_retry_jitter_seconds),
            max(0, self._settings.webhook_auto_retry_max_delay_seconds - capped_delay),
        )
        if jitter_limit <= 0:
            return capped_delay
        digest = hashlib.sha256(f"{event_id}:{current_retry_attempt + 1}".encode("utf-8")).digest()
        jitter_offset = int.from_bytes(digest[:2], "big") % (jitter_limit + 1)
        return capped_delay + jitter_offset

    def _mark_dead_letter(self, *, event_id: str, reason: str) -> None:
        now = utc_now_iso()
        self._db.execute(
            """
            UPDATE webhook_events
            SET dead_lettered_at = ?, dead_letter_reason = ?, updated_at = ?
            WHERE id = ?
            """,
            (now, reason, now, event_id),
        )
