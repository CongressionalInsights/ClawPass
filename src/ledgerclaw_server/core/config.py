from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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
    webhook_timeout_seconds: float
    webhook_secret: str | None


def load_settings() -> Settings:
    expected_origin = os.getenv("LEDGERCLAW_EXPECTED_ORIGIN", "http://localhost:8081")
    expected_origins_raw = os.getenv("LEDGERCLAW_EXPECTED_ORIGINS", "")
    expected_origins = [origin.strip() for origin in expected_origins_raw.split(",") if origin.strip()]
    if expected_origin not in expected_origins:
        expected_origins.append(expected_origin)

    db_path = Path(os.getenv("LEDGERCLAW_DB_PATH", "ledgerclaw.db")).expanduser().resolve()

    return Settings(
        db_path=db_path,
        host=os.getenv("LEDGERCLAW_HOST", "0.0.0.0"),
        port=int(os.getenv("LEDGERCLAW_PORT", "8081")),
        rp_id=os.getenv("LEDGERCLAW_RP_ID", "localhost"),
        rp_name=os.getenv("LEDGERCLAW_RP_NAME", "LedgerClaw"),
        expected_origin=expected_origin,
        expected_origins=expected_origins,
        webauthn_timeout_ms=int(os.getenv("LEDGERCLAW_WEBAUTHN_TIMEOUT_MS", "60000")),
        challenge_ttl_minutes=int(os.getenv("LEDGERCLAW_CHALLENGE_TTL_MINUTES", "10")),
        approval_default_ttl_minutes=int(os.getenv("LEDGERCLAW_APPROVAL_DEFAULT_TTL_MINUTES", "60")),
        webhook_timeout_seconds=float(os.getenv("LEDGERCLAW_WEBHOOK_TIMEOUT_SECONDS", "5")),
        webhook_secret=os.getenv("LEDGERCLAW_WEBHOOK_SECRET") or None,
    )
