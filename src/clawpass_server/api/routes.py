from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from clawpass_server.core.schemas import (
    ApprovalRequestResponse,
    ApproverSummary,
    CancelApprovalRequest,
    CreateApprovalRequest,
    DecisionCompleteRequest,
    DecisionCompleteResponse,
    DecisionStartRequest,
    DecisionStartResponse,
    EthereumSignerChallengeRequest,
    EthereumSignerChallengeResponse,
    EthereumSignerVerifyRequest,
    EthereumSignerVerifyResponse,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterCompleteResponse,
    WebAuthnRegisterStartRequest,
    WebAuthnRegisterStartResponse,
    WebhookDeliverySummary,
    WebhookEndpointSummary,
    WebhookEventResponse,
    WebhookPruneResult,
)
from clawpass_server.core.service import ClawPassService


def get_router(get_service: callable) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["clawpass"])

    def service() -> ClawPassService:
        return get_service()

    @router.post("/webauthn/register/start", response_model=WebAuthnRegisterStartResponse)
    def webauthn_register_start(payload: WebAuthnRegisterStartRequest, svc: ClawPassService = Depends(service)) -> WebAuthnRegisterStartResponse:
        return svc.start_webauthn_registration(payload)

    @router.post("/webauthn/register/complete", response_model=WebAuthnRegisterCompleteResponse)
    def webauthn_register_complete(payload: WebAuthnRegisterCompleteRequest, svc: ClawPassService = Depends(service)) -> WebAuthnRegisterCompleteResponse:
        return svc.complete_webauthn_registration(payload)

    @router.post("/approval-requests", response_model=ApprovalRequestResponse)
    def create_approval_request(payload: CreateApprovalRequest, svc: ClawPassService = Depends(service)) -> ApprovalRequestResponse:
        return svc.create_approval_request(payload)

    @router.get("/approval-requests", response_model=list[ApprovalRequestResponse])
    def list_approval_requests(status: str | None = Query(default=None), svc: ClawPassService = Depends(service)) -> list[ApprovalRequestResponse]:
        return svc.list_approval_requests(status=status)

    @router.get("/approval-requests/{request_id}", response_model=ApprovalRequestResponse)
    def get_approval_request(request_id: str, svc: ClawPassService = Depends(service)) -> ApprovalRequestResponse:
        return svc.get_approval_request(request_id)

    @router.post("/approval-requests/{request_id}/cancel", response_model=ApprovalRequestResponse)
    def cancel_approval_request(
        request_id: str,
        payload: CancelApprovalRequest,
        svc: ClawPassService = Depends(service),
    ) -> ApprovalRequestResponse:
        return svc.cancel_approval_request(request_id, reason=payload.reason)

    @router.post("/approval-requests/{request_id}/decision/start", response_model=DecisionStartResponse)
    def start_decision(
        request_id: str,
        payload: DecisionStartRequest,
        svc: ClawPassService = Depends(service),
    ) -> DecisionStartResponse:
        return svc.start_decision(request_id, payload)

    @router.post("/approval-requests/{request_id}/decision/complete", response_model=DecisionCompleteResponse)
    def complete_decision(
        request_id: str,
        payload: DecisionCompleteRequest,
        svc: ClawPassService = Depends(service),
    ) -> DecisionCompleteResponse:
        request = svc.complete_decision(request_id, payload)
        return DecisionCompleteResponse(request=request)

    @router.post("/signers/ethereum/challenge", response_model=EthereumSignerChallengeResponse)
    def ethereum_signer_challenge(
        payload: EthereumSignerChallengeRequest,
        svc: ClawPassService = Depends(service),
    ) -> EthereumSignerChallengeResponse:
        return svc.start_ethereum_signer_challenge(payload)

    @router.post("/signers/ethereum/verify", response_model=EthereumSignerVerifyResponse)
    def ethereum_signer_verify(
        payload: EthereumSignerVerifyRequest,
        svc: ClawPassService = Depends(service),
    ) -> EthereumSignerVerifyResponse:
        return svc.verify_ethereum_signer(payload)

    @router.get("/approvers/{approver_id}/summary", response_model=ApproverSummary)
    def approver_summary(approver_id: str, svc: ClawPassService = Depends(service)) -> ApproverSummary:
        return svc.get_approver_summary(approver_id)

    @router.get("/webhook-events", response_model=list[WebhookEventResponse])
    def webhook_events(
        request_id: str | None = Query(default=None),
        status: str | None = Query(default=None),
        event_type: str | None = Query(default=None),
        limit: int = Query(default=200, ge=1, le=200),
        cursor: str | None = Query(default=None),
        svc: ClawPassService = Depends(service),
    ) -> list[WebhookEventResponse]:
        return svc.list_webhook_events(
            request_id=request_id,
            status=status,
            event_type=event_type,
            limit=limit,
            cursor=cursor,
        )

    @router.get("/webhook-summary", response_model=WebhookDeliverySummary)
    def webhook_summary(svc: ClawPassService = Depends(service)) -> WebhookDeliverySummary:
        return svc.get_webhook_delivery_summary()

    @router.get("/webhook-endpoints/summary", response_model=list[WebhookEndpointSummary])
    def webhook_endpoint_summaries(
        limit: int = Query(default=20, ge=1, le=100),
        svc: ClawPassService = Depends(service),
    ) -> list[WebhookEndpointSummary]:
        return svc.list_webhook_endpoint_summaries(limit=limit)

    @router.post("/webhook-events/prune", response_model=WebhookPruneResult)
    def prune_webhook_events(svc: ClawPassService = Depends(service)) -> WebhookPruneResult:
        return svc.prune_webhook_history(emit_audit=True, actor="system")

    @router.post("/webhook-events/{event_id}/redeliver", response_model=WebhookEventResponse)
    def redeliver_webhook_event(event_id: str, svc: ClawPassService = Depends(service)) -> WebhookEventResponse:
        return svc.redeliver_webhook_event(event_id)

    @router.post("/webhook-events/{event_id}/retry-now", response_model=WebhookEventResponse)
    def retry_webhook_event_now(event_id: str, svc: ClawPassService = Depends(service)) -> WebhookEventResponse:
        return svc.retry_webhook_event_now(event_id)

    return router
