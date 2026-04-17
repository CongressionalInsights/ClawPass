from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


SCHEMA_SQL = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS approvers (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY,
  approver_id TEXT NOT NULL,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports_json TEXT NOT NULL DEFAULT '[]',
  aaguid TEXT,
  label TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  is_ledger INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ethereum_signers (
  id TEXT PRIMARY KEY,
  approver_id TEXT NOT NULL,
  address TEXT NOT NULL UNIQUE,
  chain_id INTEGER,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS approval_requests (
  id TEXT PRIMARY KEY,
  action_type TEXT NOT NULL,
  action_ref TEXT,
  action_hash TEXT NOT NULL,
  requester_id TEXT,
  risk_level TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  status TEXT NOT NULL,
  decision TEXT,
  approver_id TEXT,
  method TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  nonce TEXT NOT NULL,
  callback_url TEXT
);

CREATE TABLE IF NOT EXISTS decision_challenges (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  approver_id TEXT NOT NULL,
  method TEXT NOT NULL,
  decision TEXT NOT NULL,
  challenge TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS webauthn_registration_sessions (
  id TEXT PRIMARY KEY,
  approver_id TEXT NOT NULL,
  challenge TEXT NOT NULL,
  options_json TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  is_ledger INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ethereum_signer_sessions (
  id TEXT PRIMARY KEY,
  approver_id TEXT NOT NULL,
  address TEXT NOT NULL,
  challenge_json TEXT NOT NULL,
  challenge_digest TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS webhook_events (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  callback_url TEXT,
  status TEXT NOT NULL,
  last_error TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  lease_owner TEXT,
  lease_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  actor TEXT,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_requests_status_expires
ON approval_requests(status, expires_at);

CREATE INDEX IF NOT EXISTS idx_decision_challenges_request
ON decision_challenges(request_id, created_at);

CREATE INDEX IF NOT EXISTS idx_webhook_events_status_lease_created
ON webhook_events(status, lease_expires_at, created_at);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def ensure_ready(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA_SQL)
            self._ensure_webhook_event_columns(connection)
            connection.commit()

    def _ensure_webhook_event_columns(self, connection: sqlite3.Connection) -> None:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(webhook_events)").fetchall()}
        if "lease_owner" not in columns:
            connection.execute("ALTER TABLE webhook_events ADD COLUMN lease_owner TEXT")
        if "lease_expires_at" not in columns:
            connection.execute("ALTER TABLE webhook_events ADD COLUMN lease_expires_at TEXT")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_webhook_events_status_lease_created ON webhook_events(status, lease_expires_at, created_at)"
        )

    def fetchone(self, query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(query, params).fetchone()
        return dict(row) if row else None

    def fetchall(self, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        with self.connect() as connection:
            connection.execute(query, params)
            connection.commit()

    def execute_rowcount(self, query: str, params: tuple[Any, ...] = ()) -> int:
        with self.connect() as connection:
            cursor = connection.execute(query, params)
            connection.commit()
            return cursor.rowcount

    def execute_many(self, statements: list[tuple[str, tuple[Any, ...]]]) -> None:
        with self.connect() as connection:
            for query, params in statements:
                connection.execute(query, params)
            connection.commit()
