from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

from ledgerclaw_server.core.utils import json_dumps, token_urlsafe, utc_now_iso


ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


@dataclass(slots=True)
class EthereumChallenge:
    typed_data: dict[str, Any]
    digest: str


class EthereumAdapter:
    def build_signer_enrollment_challenge(
        self,
        *,
        approver_id: str,
        address: str,
        chain_id: int,
        expires_at: str,
    ) -> EthereumChallenge:
        nonce = token_urlsafe(12)
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "SignerEnrollment": [
                    {"name": "approverId", "type": "string"},
                    {"name": "address", "type": "address"},
                    {"name": "nonce", "type": "string"},
                    {"name": "issuedAt", "type": "string"},
                    {"name": "expiresAt", "type": "string"},
                ],
            },
            "primaryType": "SignerEnrollment",
            "domain": {
                "name": "LedgerClaw",
                "version": "1",
                "chainId": chain_id,
                "verifyingContract": ZERO_ADDRESS,
            },
            "message": {
                "approverId": approver_id,
                "address": address,
                "nonce": nonce,
                "issuedAt": utc_now_iso(),
                "expiresAt": expires_at,
            },
        }
        return EthereumChallenge(typed_data=typed_data, digest=self._digest(typed_data))

    def build_approval_decision_challenge(
        self,
        *,
        request_id: str,
        decision: str,
        action_hash: str,
        chain_id: int,
        nonce: str,
        expires_at: str,
    ) -> EthereumChallenge:
        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "ApprovalDecision": [
                    {"name": "requestId", "type": "string"},
                    {"name": "decision", "type": "string"},
                    {"name": "actionHash", "type": "string"},
                    {"name": "nonce", "type": "string"},
                    {"name": "issuedAt", "type": "string"},
                    {"name": "expiresAt", "type": "string"},
                ],
            },
            "primaryType": "ApprovalDecision",
            "domain": {
                "name": "LedgerClaw",
                "version": "1",
                "chainId": chain_id,
                "verifyingContract": ZERO_ADDRESS,
            },
            "message": {
                "requestId": request_id,
                "decision": decision,
                "actionHash": action_hash,
                "nonce": nonce,
                "issuedAt": utc_now_iso(),
                "expiresAt": expires_at,
            },
        }
        return EthereumChallenge(typed_data=typed_data, digest=self._digest(typed_data))

    def verify_signature(self, *, typed_data: dict[str, Any], signature: str) -> str:
        signable = encode_typed_data(full_message=typed_data)
        return Account.recover_message(signable, signature=signature).lower()

    def _digest(self, typed_data: dict[str, Any]) -> str:
        return hashlib.sha256(json_dumps(typed_data).encode("utf-8")).hexdigest()
