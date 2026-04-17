from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ledgerclaw_server.core.schemas import (
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
    WebhookEventResponse,
)
from ledgerclaw_server.core.service import LedgerClawService


def get_router(get_service: callable) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["clawpass"])

    def service() -> LedgerClawService:
        return get_service()

    @router.post("/webauthn/register/start", response_model=WebAuthnRegisterStartResponse)
    def webauthn_register_start(payload: WebAuthnRegisterStartRequest, svc: LedgerClawService = Depends(service)) -> WebAuthnRegisterStartResponse:
        return svc.start_webauthn_registration(payload)

    @router.post("/webauthn/register/complete", response_model=WebAuthnRegisterCompleteResponse)
    def webauthn_register_complete(payload: WebAuthnRegisterCompleteRequest, svc: LedgerClawService = Depends(service)) -> WebAuthnRegisterCompleteResponse:
        return svc.complete_webauthn_registration(payload)

    @router.post("/approval-requests", response_model=ApprovalRequestResponse)
    def create_approval_request(payload: CreateApprovalRequest, svc: LedgerClawService = Depends(service)) -> ApprovalRequestResponse:
        return svc.create_approval_request(payload)

    @router.get("/approval-requests", response_model=list[ApprovalRequestResponse])
    def list_approval_requests(status: str | None = Query(default=None), svc: LedgerClawService = Depends(service)) -> list[ApprovalRequestResponse]:
        return svc.list_approval_requests(status=status)

    @router.get("/approval-requests/{request_id}", response_model=ApprovalRequestResponse)
    def get_approval_request(request_id: str, svc: LedgerClawService = Depends(service)) -> ApprovalRequestResponse:
        return svc.get_approval_request(request_id)

    @router.post("/approval-requests/{request_id}/cancel", response_model=ApprovalRequestResponse)
    def cancel_approval_request(
        request_id: str,
        payload: CancelApprovalRequest,
        svc: LedgerClawService = Depends(service),
    ) -> ApprovalRequestResponse:
        return svc.cancel_approval_request(request_id, reason=payload.reason)

    @router.post("/approval-requests/{request_id}/decision/start", response_model=DecisionStartResponse)
    def start_decision(
        request_id: str,
        payload: DecisionStartRequest,
        svc: LedgerClawService = Depends(service),
    ) -> DecisionStartResponse:
        return svc.start_decision(request_id, payload)

    @router.post("/approval-requests/{request_id}/decision/complete", response_model=DecisionCompleteResponse)
    def complete_decision(
        request_id: str,
        payload: DecisionCompleteRequest,
        svc: LedgerClawService = Depends(service),
    ) -> DecisionCompleteResponse:
        request = svc.complete_decision(request_id, payload)
        return DecisionCompleteResponse(request=request)

    @router.post("/signers/ethereum/challenge", response_model=EthereumSignerChallengeResponse)
    def ethereum_signer_challenge(
        payload: EthereumSignerChallengeRequest,
        svc: LedgerClawService = Depends(service),
    ) -> EthereumSignerChallengeResponse:
        return svc.start_ethereum_signer_challenge(payload)

    @router.post("/signers/ethereum/verify", response_model=EthereumSignerVerifyResponse)
    def ethereum_signer_verify(
        payload: EthereumSignerVerifyRequest,
        svc: LedgerClawService = Depends(service),
    ) -> EthereumSignerVerifyResponse:
        return svc.verify_ethereum_signer(payload)

    @router.get("/approvers/{approver_id}/summary", response_model=ApproverSummary)
    def approver_summary(approver_id: str, svc: LedgerClawService = Depends(service)) -> ApproverSummary:
        return svc.get_approver_summary(approver_id)

    @router.get("/webhook-events", response_model=list[WebhookEventResponse])
    def webhook_events(
        request_id: str | None = Query(default=None),
        svc: LedgerClawService = Depends(service),
    ) -> list[WebhookEventResponse]:
        return svc.list_webhook_events(request_id=request_id)

    return router
