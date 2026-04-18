from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ApproverIdentityIn(BaseModel):
    approver_id: str | None = None
    email: str | None = None
    display_name: str | None = None


class BootstrapStatusResponse(BaseModel):
    initialized: bool
    bootstrap_configured: bool


class BootstrapStartRequest(BaseModel):
    bootstrap_token: str
    email: str
    display_name: str | None = None


class BootstrapStartResponse(BaseModel):
    session_id: str
    public_key_options: dict[str, Any]


class BootstrapCompleteRequest(BaseModel):
    session_id: str
    credential: dict[str, Any]
    label: str | None = None


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
    producer_id: str | None
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
    approval_url: str | None


class DecisionStartRequest(BaseModel):
    approver_id: str | None = None
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


class ApprovalLinkResponse(BaseModel):
    id: str
    producer_id: str | None
    action_type: str
    action_ref: str | None
    risk_level: str
    status: str
    created_at: str
    expires_at: str
    approval_url: str


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


class LoginStartRequest(BaseModel):
    email: str


class AdminLoginStartResponse(BaseModel):
    session_id: str
    public_key_options: dict[str, Any]


class AdminLoginCompleteRequest(BaseModel):
    session_id: str
    credential: dict[str, Any]


class AdminSessionResponse(BaseModel):
    admin_id: str | None
    approver_id: str
    email: str
    display_name: str | None
    passkey_count: int
    ledger_webauthn_count: int
    ethereum_signer_count: int
    is_admin: bool


class ApproverInviteCreateRequest(BaseModel):
    email: str
    display_name: str | None = None
    expires_in_minutes: int | None = None
    next_path: str | None = None


class ApproverInviteResponse(BaseModel):
    token: str
    approver_id: str
    email: str
    display_name: str | None
    invite_url: str
    expires_at: str
    consumed_at: str | None


class ApproverResponse(BaseModel):
    id: str
    email: str
    display_name: str | None
    created_at: str
    passkey_count: int
    ledger_webauthn_count: int
    ethereum_signer_count: int


class ProducerCreateRequest(BaseModel):
    name: str
    description: str | None = None


class ProducerResponse(BaseModel):
    id: str
    name: str
    description: str | None
    created_at: str
    revoked_at: str | None


class ProducerKeyCreateRequest(BaseModel):
    label: str | None = None


class ProducerKeyResponse(BaseModel):
    key_id: str
    producer_id: str
    api_key: str | None
    created_at: str
    label: str | None


class WebhookEventResponse(BaseModel):
    id: str
    request_id: str
    event_type: str
    callback_url: str | None = None
    status: str
    last_error: str | None
    attempt_count: int
    available_at: str | None = None
    lease_expires_at: str | None = None
    retry_parent_id: str | None = None
    retry_attempt: int = 0
    dead_lettered_at: str | None = None
    dead_letter_reason: str | None = None
    created_at: str
    updated_at: str


class WebhookDeliverySummary(BaseModel):
    total_events: int
    backlog_count: int
    leased_backlog_count: int
    stalled_backlog_count: int
    scheduled_retry_count: int
    dead_lettered_count: int
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
    oldest_stalled_at: str | None
    last_event_at: str | None
    health_state: str
    alerts: list[str]


class WebhookEndpointSummary(BaseModel):
    callback_url: str
    muted_until: str | None
    mute_reason: str | None
    consecutive_failure_count: int
    total_events: int
    queued_count: int
    stalled_count: int
    delivered_count: int
    failed_count: int
    dead_lettered_count: int
    attempted_count: int
    failure_rate: float
    next_attempt_at: str | None
    last_event_at: str | None
    latest_error: str | None
    health_state: str


class WebhookPruneResult(BaseModel):
    deleted_delivered_or_skipped: int
    deleted_retry_history_events: int
    total_deleted: int
    delivered_or_skipped_cutoff: str | None
    retry_history_cutoff: str | None


class WebhookEndpointMuteRequest(BaseModel):
    callback_url: str
    muted_for_seconds: int | None = None
    reason: str | None = None


class WebhookEndpointUnmuteRequest(BaseModel):
    callback_url: str


class WebhookEndpointControlResponse(BaseModel):
    callback_url: str
    muted_until: str | None
    mute_reason: str | None
    consecutive_failure_count: int


class WebhookPruneHistoryEntry(BaseModel):
    created_at: str
    actor: str | None
    deleted_delivered_or_skipped: int
    deleted_retry_history_events: int
    total_deleted: int
    delivered_or_skipped_cutoff: str | None
    retry_history_cutoff: str | None


class ApproverSummary(BaseModel):
    id: str
    email: str
    display_name: str | None
    passkey_count: int
    ledger_webauthn_count: int
    ethereum_signer_count: int


class ApiError(BaseModel):
    detail: str
