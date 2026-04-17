from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from clawpass_server.core.utils import stable_id


@dataclass(slots=True)
class Settings:
    db_path: Path
    host: str
    port: int
    rp_id: str
    rp_name: str
    expected_origin: str
    expected_origins: list[str]
    webauthn_timeout_ms: int
    challenge_ttl_minutes: int
    approval_default_ttl_minutes: int
    instance_id: str
    webhook_timeout_seconds: float
    webhook_delivery_lease_seconds: int
    webhook_backlog_alert_threshold: int
    webhook_backlog_alert_after_seconds: int
    webhook_failure_rate_alert_threshold: float
    webhook_secret: str | None


def _env(primary: str, legacy: str, default: str) -> str:
    return os.getenv(primary) or os.getenv(legacy) or default


def load_settings() -> Settings:
    expected_origin = _env("CLAWPASS_EXPECTED_ORIGIN", "LEDGERCLAW_EXPECTED_ORIGIN", "http://localhost:8081")
    expected_origins_raw = _env("CLAWPASS_EXPECTED_ORIGINS", "LEDGERCLAW_EXPECTED_ORIGINS", "")
    expected_origins = [origin.strip() for origin in expected_origins_raw.split(",") if origin.strip()]
    if expected_origin not in expected_origins:
        expected_origins.append(expected_origin)

    db_path = Path(_env("CLAWPASS_DB_PATH", "LEDGERCLAW_DB_PATH", "clawpass.db")).expanduser().resolve()

    return Settings(
        db_path=db_path,
        host=_env("CLAWPASS_HOST", "LEDGERCLAW_HOST", "0.0.0.0"),
        port=int(_env("CLAWPASS_PORT", "LEDGERCLAW_PORT", "8081")),
        rp_id=_env("CLAWPASS_RP_ID", "LEDGERCLAW_RP_ID", "localhost"),
        rp_name=_env("CLAWPASS_RP_NAME", "LEDGERCLAW_RP_NAME", "ClawPass"),
        expected_origin=expected_origin,
        expected_origins=expected_origins,
        webauthn_timeout_ms=int(_env("CLAWPASS_WEBAUTHN_TIMEOUT_MS", "LEDGERCLAW_WEBAUTHN_TIMEOUT_MS", "60000")),
        challenge_ttl_minutes=int(_env("CLAWPASS_CHALLENGE_TTL_MINUTES", "LEDGERCLAW_CHALLENGE_TTL_MINUTES", "10")),
        approval_default_ttl_minutes=int(_env("CLAWPASS_APPROVAL_DEFAULT_TTL_MINUTES", "LEDGERCLAW_APPROVAL_DEFAULT_TTL_MINUTES", "60")),
        instance_id=_env("CLAWPASS_INSTANCE_ID", "LEDGERCLAW_INSTANCE_ID", stable_id("instance")),
        webhook_timeout_seconds=float(_env("CLAWPASS_WEBHOOK_TIMEOUT_SECONDS", "LEDGERCLAW_WEBHOOK_TIMEOUT_SECONDS", "5")),
        webhook_delivery_lease_seconds=int(
            _env("CLAWPASS_WEBHOOK_DELIVERY_LEASE_SECONDS", "LEDGERCLAW_WEBHOOK_DELIVERY_LEASE_SECONDS", "30")
        ),
        webhook_backlog_alert_threshold=int(
            _env("CLAWPASS_WEBHOOK_BACKLOG_ALERT_THRESHOLD", "LEDGERCLAW_WEBHOOK_BACKLOG_ALERT_THRESHOLD", "1")
        ),
        webhook_backlog_alert_after_seconds=int(
            _env("CLAWPASS_WEBHOOK_BACKLOG_ALERT_AFTER_SECONDS", "LEDGERCLAW_WEBHOOK_BACKLOG_ALERT_AFTER_SECONDS", "30")
        ),
        webhook_failure_rate_alert_threshold=float(
            _env("CLAWPASS_WEBHOOK_FAILURE_RATE_ALERT_THRESHOLD", "LEDGERCLAW_WEBHOOK_FAILURE_RATE_ALERT_THRESHOLD", "0.25")
        ),
        webhook_secret=os.getenv("CLAWPASS_WEBHOOK_SECRET") or os.getenv("LEDGERCLAW_WEBHOOK_SECRET") or None,
    )
