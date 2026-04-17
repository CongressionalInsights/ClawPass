from __future__ import annotations

from typing import Any

from clawpass_server.core.database import Database
from clawpass_server.core.utils import json_dumps, stable_id, utc_now_iso


class AuditLogger:
    def __init__(self, db: Database) -> None:
        self._db = db

    def log(
        self,
        *,
        event_type: str,
        resource_type: str,
        resource_id: str | None,
        actor: str | None,
        payload: dict[str, Any],
    ) -> None:
        self._db.execute(
            """
            INSERT INTO audit_events(id, event_type, actor, resource_type, resource_id, payload_json, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stable_id("audit"),
                event_type,
                actor,
                resource_type,
                resource_id,
                json_dumps(payload),
                utc_now_iso(),
            ),
        )
