from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from clawpass_server.core.config import Settings


@dataclass(slots=True)
class RegistrationVerification:
    credential_id: str
    credential_public_key: str
    sign_count: int
    aaguid: str | None


class WebAuthnAdapter:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def generate_registration(self, *, user_id: str, user_name: str, user_display_name: str, exclude_credential_ids: list[str], is_ledger: bool) -> tuple[dict[str, Any], str]:
        selection = AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM if is_ledger else None,
        )
        options = generate_registration_options(
            rp_id=self._settings.rp_id,
            rp_name=self._settings.rp_name,
            user_id=user_id.encode("utf-8"),
            user_name=user_name,
            user_display_name=user_display_name,
            timeout=self._settings.webauthn_timeout_ms,
            authenticator_selection=selection,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_id))
                for credential_id in exclude_credential_ids
            ],
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )
        payload = json.loads(options_to_json(options))
        if is_ledger:
            payload.setdefault("hints", ["security-key", "hybrid"])
        challenge = str(payload["challenge"])
        return payload, challenge

    def verify_registration(self, *, credential: dict[str, Any], challenge: str) -> RegistrationVerification:
        last_error: Exception | None = None
        for origin in self._settings.expected_origins:
            try:
                verification = verify_registration_response(
                    credential=credential,
                    expected_challenge=base64url_to_bytes(challenge),
                    expected_origin=origin,
                    expected_rp_id=self._settings.rp_id,
                    require_user_verification=False,
                )
                return RegistrationVerification(
                    credential_id=bytes_to_base64url(verification.credential_id),
                    credential_public_key=bytes_to_base64url(verification.credential_public_key),
                    sign_count=int(verification.sign_count),
                    aaguid=str(verification.aaguid) if verification.aaguid else None,
                )
            except Exception as exc:  # pragma: no cover - validated via integration tests using monkeypatch
                last_error = exc
        raise ValueError(f"registration verification failed: {last_error}")

    def generate_authentication(self, *, allowed_credential_ids: list[str]) -> tuple[dict[str, Any], str]:
        options = generate_authentication_options(
            rp_id=self._settings.rp_id,
            timeout=self._settings.webauthn_timeout_ms,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_id))
                for credential_id in allowed_credential_ids
            ],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        payload = json.loads(options_to_json(options))
        challenge = str(payload["challenge"])
        return payload, challenge

    def verify_authentication(
        self,
        *,
        credential: dict[str, Any],
        challenge: str,
        credential_public_key: str,
        credential_current_sign_count: int,
    ) -> int:
        last_error: Exception | None = None
        for origin in self._settings.expected_origins:
            try:
                verification = verify_authentication_response(
                    credential=credential,
                    expected_challenge=base64url_to_bytes(challenge),
                    expected_origin=origin,
                    expected_rp_id=self._settings.rp_id,
                    credential_public_key=base64url_to_bytes(credential_public_key),
                    credential_current_sign_count=credential_current_sign_count,
                    require_user_verification=False,
                )
                return int(verification.new_sign_count)
            except Exception as exc:  # pragma: no cover - validated via integration tests using monkeypatch
                last_error = exc
        raise ValueError(f"authentication verification failed: {last_error}")
