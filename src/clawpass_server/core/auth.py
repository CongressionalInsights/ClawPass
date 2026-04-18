from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac


SESSION_COOKIE = "clawpass_session"
ADMIN_SESSION_COOKIE = "clawpass_admin_session"
ADMIN_CSRF_COOKIE = "clawpass_csrf"
CSRF_HEADER = "X-ClawPass-CSRF"


@dataclass(slots=True)
class HumanSessionPrincipal:
    approver_id: str
    email: str
    display_name: str | None
    session_id: str
    csrf_token: str
    admin_id: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.admin_id is not None


AdminSessionPrincipal = HumanSessionPrincipal


@dataclass(slots=True)
class ProducerPrincipal:
    producer_id: str
    key_id: str
    name: str


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def secret_matches(secret: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), expected_hash)


def make_api_key(public_key_id: str, secret: str) -> str:
    return f"cpk_{public_key_id}.{secret}"


def split_api_key(raw: str) -> tuple[str, str] | None:
    value = raw.strip()
    if not value.startswith("cpk_"):
        return None
    public_key_id, sep, secret = value[4:].partition(".")
    if not sep or not public_key_id or not secret:
        return None
    return public_key_id, secret


def extract_bearer_token(header_value: str | None) -> str | None:
    if not header_value:
        return None
    scheme, _, token = header_value.strip().partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()
