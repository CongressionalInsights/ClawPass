from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def add_minutes_iso(minutes: int) -> str:
    return (utc_now() + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def add_seconds_iso(seconds: int) -> str:
    return (utc_now() + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def token_urlsafe(size: int = 32) -> str:
    return secrets.token_urlsafe(size)


def json_dumps(data: object) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def stable_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"
