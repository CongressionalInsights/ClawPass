from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from clawpass_server.core.utils import stable_id


@dataclass(slots=True)
class Settings:
    db_path: Path
    host: str
    port: int
    base_url: str
    rp_id: str
    rp_name: str
    expected_origin: str
    expected_origins: list[str]
    webauthn_timeout_ms: int
    challenge_ttl_minutes: int
    approval_default_ttl_minutes: int
    admin_session_ttl_minutes: int
    instance_id: str
    session_secret: str
    session_secret_configured: bool
    bootstrap_token: str | None
    deployment_mode: str
    webhook_timeout_seconds: float
    webhook_delivery_lease_seconds: int
    webhook_retry_poll_seconds: int
    webhook_auto_retry_limit: int
    webhook_auto_retry_base_delay_seconds: int
    webhook_auto_retry_max_delay_seconds: int
    webhook_auto_retry_jitter_seconds: int
    webhook_backlog_alert_threshold: int
    webhook_backlog_alert_after_seconds: int
    webhook_failure_rate_alert_threshold: float
    webhook_event_retention_days: int
    webhook_retry_history_retention_days: int
    webhook_endpoint_auto_mute_threshold: int
    webhook_endpoint_auto_mute_seconds: int
    webhook_secret: str | None


def _env(primary: str, legacy: str, default: str) -> str:
    return os.getenv(primary) or os.getenv(legacy) or default


def _env_or_file(primary: str, legacy: str) -> str | None:
    direct = os.getenv(primary) or os.getenv(legacy)
    if direct:
        return direct
    file_value = os.getenv(f"{primary}_FILE") or os.getenv(f"{legacy}_FILE")
    if not file_value:
        return None
    return Path(file_value).expanduser().read_text(encoding="utf-8").strip()


def is_local_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.hostname in {"localhost", "127.0.0.1"}


def validate_settings(settings: Settings, *, initialized: bool) -> None:
    base_url = urlparse(settings.base_url)
    expected_origin = urlparse(settings.expected_origin)
    if base_url.scheme not in {"http", "https"}:
        raise ValueError("CLAWPASS_BASE_URL must use http or https.")
    if expected_origin.scheme not in {"http", "https"}:
        raise ValueError("CLAWPASS_EXPECTED_ORIGIN must use http or https.")
    if settings.expected_origin not in settings.expected_origins:
        raise ValueError("CLAWPASS_EXPECTED_ORIGIN must be present in CLAWPASS_EXPECTED_ORIGINS.")
    if (base_url.scheme, base_url.netloc) != (expected_origin.scheme, expected_origin.netloc):
        raise ValueError("CLAWPASS_BASE_URL and CLAWPASS_EXPECTED_ORIGIN must resolve to the same origin.")
    if expected_origin.hostname and settings.rp_id not in {expected_origin.hostname}:
        if not expected_origin.hostname.endswith(f".{settings.rp_id}"):
            raise ValueError("CLAWPASS_RP_ID must match or be a registrable suffix of the expected origin host.")
    non_local = not is_local_url(settings.base_url)
    strict = settings.deployment_mode.lower() == "production" or non_local
    if strict and not settings.session_secret_configured:
        raise ValueError("CLAWPASS_SESSION_SECRET or CLAWPASS_SESSION_SECRET_FILE is required for non-local deployments.")
    if not initialized and strict and not settings.bootstrap_token:
        raise ValueError("CLAWPASS_BOOTSTRAP_TOKEN or CLAWPASS_BOOTSTRAP_TOKEN_FILE is required before first bootstrap.")


def load_settings() -> Settings:
    expected_origin = _env("CLAWPASS_EXPECTED_ORIGIN", "LEDGERCLAW_EXPECTED_ORIGIN", "http://localhost:8081")
    expected_origins_raw = _env("CLAWPASS_EXPECTED_ORIGINS", "LEDGERCLAW_EXPECTED_ORIGINS", "")
    expected_origins = [origin.strip() for origin in expected_origins_raw.split(",") if origin.strip()]
    if expected_origin not in expected_origins:
        expected_origins.append(expected_origin)

    db_path = Path(_env("CLAWPASS_DB_PATH", "LEDGERCLAW_DB_PATH", "clawpass.db")).expanduser().resolve()

    session_secret = _env_or_file("CLAWPASS_SESSION_SECRET", "LEDGERCLAW_SESSION_SECRET")
    bootstrap_token = _env_or_file("CLAWPASS_BOOTSTRAP_TOKEN", "LEDGERCLAW_BOOTSTRAP_TOKEN")

    return Settings(
        db_path=db_path,
        host=_env("CLAWPASS_HOST", "LEDGERCLAW_HOST", "0.0.0.0"),
        port=int(_env("CLAWPASS_PORT", "LEDGERCLAW_PORT", "8081")),
        base_url=_env("CLAWPASS_BASE_URL", "LEDGERCLAW_BASE_URL", expected_origin).rstrip("/"),
        rp_id=_env("CLAWPASS_RP_ID", "LEDGERCLAW_RP_ID", "localhost"),
        rp_name=_env("CLAWPASS_RP_NAME", "LEDGERCLAW_RP_NAME", "ClawPass"),
        expected_origin=expected_origin,
        expected_origins=expected_origins,
        webauthn_timeout_ms=int(_env("CLAWPASS_WEBAUTHN_TIMEOUT_MS", "LEDGERCLAW_WEBAUTHN_TIMEOUT_MS", "60000")),
        challenge_ttl_minutes=int(_env("CLAWPASS_CHALLENGE_TTL_MINUTES", "LEDGERCLAW_CHALLENGE_TTL_MINUTES", "10")),
        approval_default_ttl_minutes=int(_env("CLAWPASS_APPROVAL_DEFAULT_TTL_MINUTES", "LEDGERCLAW_APPROVAL_DEFAULT_TTL_MINUTES", "60")),
        admin_session_ttl_minutes=int(
            _env("CLAWPASS_ADMIN_SESSION_TTL_MINUTES", "LEDGERCLAW_ADMIN_SESSION_TTL_MINUTES", "720")
        ),
        instance_id=_env("CLAWPASS_INSTANCE_ID", "LEDGERCLAW_INSTANCE_ID", stable_id("instance")),
        session_secret=session_secret or stable_id("session"),
        session_secret_configured=bool(session_secret),
        bootstrap_token=bootstrap_token,
        deployment_mode=_env("CLAWPASS_DEPLOYMENT_MODE", "LEDGERCLAW_DEPLOYMENT_MODE", "development"),
        webhook_timeout_seconds=float(_env("CLAWPASS_WEBHOOK_TIMEOUT_SECONDS", "LEDGERCLAW_WEBHOOK_TIMEOUT_SECONDS", "5")),
        webhook_delivery_lease_seconds=int(
            _env("CLAWPASS_WEBHOOK_DELIVERY_LEASE_SECONDS", "LEDGERCLAW_WEBHOOK_DELIVERY_LEASE_SECONDS", "30")
        ),
        webhook_retry_poll_seconds=int(
            _env("CLAWPASS_WEBHOOK_RETRY_POLL_SECONDS", "LEDGERCLAW_WEBHOOK_RETRY_POLL_SECONDS", "5")
        ),
        webhook_auto_retry_limit=int(
            _env("CLAWPASS_WEBHOOK_AUTO_RETRY_LIMIT", "LEDGERCLAW_WEBHOOK_AUTO_RETRY_LIMIT", "2")
        ),
        webhook_auto_retry_base_delay_seconds=int(
            _env(
                "CLAWPASS_WEBHOOK_AUTO_RETRY_BASE_DELAY_SECONDS",
                "LEDGERCLAW_WEBHOOK_AUTO_RETRY_BASE_DELAY_SECONDS",
                "30",
            )
        ),
        webhook_auto_retry_max_delay_seconds=int(
            _env(
                "CLAWPASS_WEBHOOK_AUTO_RETRY_MAX_DELAY_SECONDS",
                "LEDGERCLAW_WEBHOOK_AUTO_RETRY_MAX_DELAY_SECONDS",
                "300",
            )
        ),
        webhook_auto_retry_jitter_seconds=int(
            _env(
                "CLAWPASS_WEBHOOK_AUTO_RETRY_JITTER_SECONDS",
                "LEDGERCLAW_WEBHOOK_AUTO_RETRY_JITTER_SECONDS",
                "10",
            )
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
        webhook_event_retention_days=int(
            _env("CLAWPASS_WEBHOOK_EVENT_RETENTION_DAYS", "LEDGERCLAW_WEBHOOK_EVENT_RETENTION_DAYS", "14")
        ),
        webhook_retry_history_retention_days=int(
            _env(
                "CLAWPASS_WEBHOOK_RETRY_HISTORY_RETENTION_DAYS",
                "LEDGERCLAW_WEBHOOK_RETRY_HISTORY_RETENTION_DAYS",
                "30",
            )
        ),
        webhook_endpoint_auto_mute_threshold=int(
            _env(
                "CLAWPASS_WEBHOOK_ENDPOINT_AUTO_MUTE_THRESHOLD",
                "LEDGERCLAW_WEBHOOK_ENDPOINT_AUTO_MUTE_THRESHOLD",
                "3",
            )
        ),
        webhook_endpoint_auto_mute_seconds=int(
            _env(
                "CLAWPASS_WEBHOOK_ENDPOINT_AUTO_MUTE_SECONDS",
                "LEDGERCLAW_WEBHOOK_ENDPOINT_AUTO_MUTE_SECONDS",
                "600",
            )
        ),
        webhook_secret=os.getenv("CLAWPASS_WEBHOOK_SECRET") or os.getenv("LEDGERCLAW_WEBHOOK_SECRET") or None,
    )
