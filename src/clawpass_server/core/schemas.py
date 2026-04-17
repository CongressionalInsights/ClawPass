from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ApproverIdentityIn(BaseModel):
    approver_id: str | None = None
    email: str | None = None
    display_name: str | None = None


class WebAuthnRegisterStartRequest(ApproverIdentityIn):
    label: str | None = None
    is_ledger: bool = False


class WebAuthnRegisterStartResponse(BaseModel):
    session_id: str
    approver_id: str
    public_key_options: dict[str, Any]


class WebAuthnRegisterCompleteRequest(BaseModel):
    session_id: str
    credential: dict[str, Any]
    label: str | None = None


class WebAuthnRegisterCompleteResponse(BaseModel):
    approver_id: str
    credential_id: str
    is_ledger: bool


class CreateApprovalRequest(BaseModel):
    request_id: str | None = None
    action_type: str
    action_ref: str | None = None
    action_hash: str
    requester_id: str | None = None
    risk_level: str = "low"
    metadata: dict[str, Any] = Field(default_factory=dict)
    expires_at: str | None = None
    callback_url: str | None = None


class ApprovalRequestResponse(BaseModel):
    id: str
    action_type: str
    action_ref: str | None
    action_hash: str
    requester_id: str | None
    risk_level: str
    metadata: dict[str, Any]
    status: str
    decision: str | None
    method: str | None
    approver_id: str | None
    nonce: str
    created_at: str
    expires_at: str
    decided_at: str | None
    callback_url: str | None


class DecisionStartRequest(BaseModel):
    approver_id: str
    decision: Literal["APPROVE", "DENY"]
    method: Literal["webauthn", "ledger_webauthn", "ethereum_signer"]


class DecisionStartResponse(BaseModel):
    challenge_id: str
    method: str
    expires_at: str
    payload: dict[str, Any]


class DecisionCompleteRequest(BaseModel):
    challenge_id: str
    proof: dict[str, Any]


class DecisionCompleteResponse(BaseModel):
    request: ApprovalRequestResponse


class EthereumSignerChallengeRequest(ApproverIdentityIn):
    address: str
    chain_id: int = 1


class EthereumSignerChallengeResponse(BaseModel):
    session_id: str
    approver_id: str
    typed_data: dict[str, Any]
    digest: str


class EthereumSignerVerifyRequest(BaseModel):
    session_id: str
    signature: str


class EthereumSignerVerifyResponse(BaseModel):
    approver_id: str
    address: str
    chain_id: int


class CancelApprovalRequest(BaseModel):
    reason: str | None = None


class WebhookEventResponse(BaseModel):
    id: str
    request_id: str
    event_type: str
    status: str
    last_error: str | None
    attempt_count: int
    created_at: str
    updated_at: str


class WebhookDeliverySummary(BaseModel):
    total_events: int
    backlog_count: int
    delivered_count: int
    failed_count: int
    skipped_count: int
    attempted_count: int
    failure_rate: float
    redelivery_count: int
    redelivery_backlog_count: int
    redelivery_delivered_count: int
    redelivery_failed_count: int
    oldest_queued_at: str | None
    last_event_at: str | None


class ApproverSummary(BaseModel):
    id: str
    email: str
    display_name: str | None
    passkey_count: int
    ledger_webauthn_count: int
    ethereum_signer_count: int


class ApiError(BaseModel):
    detail: str
