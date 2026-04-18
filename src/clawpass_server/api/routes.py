from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response

from clawpass_server.core.auth import ADMIN_CSRF_COOKIE, ADMIN_SESSION_COOKIE, SESSION_COOKIE
from clawpass_server.core.schemas import (
    AdminLoginCompleteRequest,
    AdminLoginStartResponse,
    AdminSessionResponse,
    ApprovalLinkResponse,
    ApprovalRequestResponse,
    ApproverInviteCreateRequest,
    ApproverInviteResponse,
    ApproverResponse,
    ApproverSummary,
    BootstrapCompleteRequest,
    BootstrapStartRequest,
    BootstrapStartResponse,
    BootstrapStatusResponse,
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
    LoginStartRequest,
    ProducerCreateRequest,
    ProducerKeyCreateRequest,
    ProducerKeyResponse,
    ProducerResponse,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterCompleteResponse,
    WebAuthnRegisterStartRequest,
    WebAuthnRegisterStartResponse,
    WebhookDeliverySummary,
    WebhookEndpointControlResponse,
    WebhookEndpointMuteRequest,
    WebhookEndpointSummary,
    WebhookEventResponse,
    WebhookPruneHistoryEntry,
    WebhookPruneResult,
    WebhookEndpointUnmuteRequest,
)
from clawpass_server.core.service import ClawPassService


def get_router(get_service: callable) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["clawpass"])

    def service() -> ClawPassService:
        return get_service()

    def _session_cookie(request: Request) -> str | None:
        return request.cookies.get(SESSION_COOKIE) or request.cookies.get(ADMIN_SESSION_COOKIE)

    def _set_session_cookies(response: Response, svc: ClawPassService, session_id: str, csrf_token: str) -> None:
        secure = svc._settings.base_url.startswith("https://")
        cookie_options = {
            "httponly": True,
            "secure": secure,
            "samesite": "lax",
            "path": "/",
        }
        response.set_cookie(SESSION_COOKIE, session_id, **cookie_options)
        response.set_cookie(ADMIN_SESSION_COOKIE, session_id, **cookie_options)
        response.set_cookie(
            ADMIN_CSRF_COOKIE,
            csrf_token,
            httponly=False,
            secure=secure,
            samesite="lax",
            path="/",
        )

    def _clear_session_cookies(response: Response, svc: ClawPassService) -> None:
        secure = svc._settings.base_url.startswith("https://")
        for cookie_name in (SESSION_COOKIE, ADMIN_SESSION_COOKIE):
            response.delete_cookie(cookie_name, path="/", secure=secure, samesite="lax")
        response.delete_cookie(ADMIN_CSRF_COOKIE, path="/", secure=secure, samesite="lax")

    def _require_human(
        request: Request,
        csrf_header: str | None = Header(default=None, alias="X-ClawPass-CSRF"),
        svc: ClawPassService = Depends(service),
    ):
        return svc.require_human_session(
            _session_cookie(request),
            csrf_token=csrf_header,
            require_csrf=request.method not in {"GET", "HEAD", "OPTIONS"},
        )

    def _require_admin(
        request: Request,
        csrf_header: str | None = Header(default=None, alias="X-ClawPass-CSRF"),
        svc: ClawPassService = Depends(service),
    ):
        return svc.require_admin_session(
            _session_cookie(request),
            csrf_token=csrf_header,
            require_csrf=request.method not in {"GET", "HEAD", "OPTIONS"},
        )

    @router.get("/setup/status", response_model=BootstrapStatusResponse)
    def bootstrap_status(svc: ClawPassService = Depends(service)) -> BootstrapStatusResponse:
        return svc.get_bootstrap_status()

    @router.post("/setup/bootstrap/start", response_model=BootstrapStartResponse)
    def setup_bootstrap_start(
        payload: BootstrapStartRequest,
        svc: ClawPassService = Depends(service),
    ) -> BootstrapStartResponse:
        return svc.start_bootstrap(payload)

    @router.post("/setup/bootstrap/complete", response_model=AdminSessionResponse)
    def setup_bootstrap_complete(
        payload: BootstrapCompleteRequest,
        response: Response,
        svc: ClawPassService = Depends(service),
    ) -> AdminSessionResponse:
        session, session_id, csrf_token = svc.complete_bootstrap(payload)
        _set_session_cookies(response, svc, session_id, csrf_token)
        return session

    @router.post("/auth/login/start", response_model=AdminLoginStartResponse)
    def login_start(
        payload: LoginStartRequest,
        svc: ClawPassService = Depends(service),
    ) -> AdminLoginStartResponse:
        return svc.start_login(payload)

    @router.post("/auth/login/complete", response_model=AdminSessionResponse)
    def login_complete(
        payload: AdminLoginCompleteRequest,
        response: Response,
        svc: ClawPassService = Depends(service),
    ) -> AdminSessionResponse:
        session, session_id, csrf_token = svc.complete_login(payload)
        _set_session_cookies(response, svc, session_id, csrf_token)
        return session

    @router.post("/auth/admin/login/start", response_model=AdminLoginStartResponse)
    def admin_login_start(svc: ClawPassService = Depends(service)) -> AdminLoginStartResponse:
        return svc.start_admin_login()

    @router.post("/auth/admin/login/complete", response_model=AdminSessionResponse)
    def admin_login_complete(
        payload: AdminLoginCompleteRequest,
        response: Response,
        svc: ClawPassService = Depends(service),
    ) -> AdminSessionResponse:
        session, session_id, csrf_token = svc.complete_admin_login(payload)
        _set_session_cookies(response, svc, session_id, csrf_token)
        return session

    @router.get("/auth/session", response_model=AdminSessionResponse)
    def human_session(principal=Depends(_require_human), svc: ClawPassService = Depends(service)) -> AdminSessionResponse:
        return svc.get_session_response(principal.approver_id)

    @router.get("/admin/session", response_model=AdminSessionResponse)
    def admin_session(principal=Depends(_require_admin), svc: ClawPassService = Depends(service)) -> AdminSessionResponse:
        return svc.get_admin_session_response(principal.admin_id)

    @router.post("/auth/logout")
    def logout(
        request: Request,
        response: Response,
        svc: ClawPassService = Depends(service),
    ) -> dict[str, bool]:
        svc.logout_session(_session_cookie(request))
        _clear_session_cookies(response, svc)
        return {"ok": True}

    @router.get("/approval-links/{request_id}", response_model=ApprovalLinkResponse)
    def approval_link(
        request_id: str,
        svc: ClawPassService = Depends(service),
    ) -> ApprovalLinkResponse:
        return svc.get_approval_link(request_id)

    @router.get("/invites/{token}", response_model=ApproverInviteResponse)
    def approver_invite(token: str, svc: ClawPassService = Depends(service)) -> ApproverInviteResponse:
        return svc.get_approver_invite(token)

    @router.post("/invites/{token}/start", response_model=WebAuthnRegisterStartResponse)
    def invite_start(
        token: str,
        svc: ClawPassService = Depends(service),
    ) -> WebAuthnRegisterStartResponse:
        return svc.start_approver_invite_enrollment(token)

    @router.post("/invites/{token}/complete", response_model=AdminSessionResponse)
    def invite_complete(
        token: str,
        payload: WebAuthnRegisterCompleteRequest,
        response: Response,
        svc: ClawPassService = Depends(service),
    ) -> AdminSessionResponse:
        session, session_id, csrf_token = svc.complete_approver_invite_enrollment(token, payload)
        _set_session_cookies(response, svc, session_id, csrf_token)
        return session

    @router.post("/webauthn/register/start", response_model=WebAuthnRegisterStartResponse)
    def webauthn_register_start(
        payload: WebAuthnRegisterStartRequest,
        principal=Depends(_require_human),
        svc: ClawPassService = Depends(service),
    ) -> WebAuthnRegisterStartResponse:
        return svc.start_webauthn_registration(
            WebAuthnRegisterStartRequest(
                approver_id=principal.approver_id,
                is_ledger=payload.is_ledger,
                label=payload.label,
            )
        )

    @router.post("/webauthn/register/complete", response_model=WebAuthnRegisterCompleteResponse)
    def webauthn_register_complete(
        payload: WebAuthnRegisterCompleteRequest,
        principal=Depends(_require_human),
        svc: ClawPassService = Depends(service),
    ) -> WebAuthnRegisterCompleteResponse:
        return svc.complete_webauthn_registration(payload)

    @router.post("/signers/ethereum/challenge", response_model=EthereumSignerChallengeResponse)
    def ethereum_signer_challenge(
        payload: EthereumSignerChallengeRequest,
        principal=Depends(_require_human),
        svc: ClawPassService = Depends(service),
    ) -> EthereumSignerChallengeResponse:
        return svc.start_ethereum_signer_challenge(
            EthereumSignerChallengeRequest(
                approver_id=principal.approver_id,
                address=payload.address,
                chain_id=payload.chain_id,
            )
        )

    @router.post("/signers/ethereum/verify", response_model=EthereumSignerVerifyResponse)
    def ethereum_signer_verify(
        payload: EthereumSignerVerifyRequest,
        principal=Depends(_require_human),
        svc: ClawPassService = Depends(service),
    ) -> EthereumSignerVerifyResponse:
        return svc.verify_ethereum_signer(payload)

    @router.get("/operator/approvers", response_model=list[ApproverResponse])
    def list_approvers(principal=Depends(_require_admin), svc: ClawPassService = Depends(service)) -> list[ApproverResponse]:
        return svc.list_approvers()

    @router.get("/operator/approver-invites", response_model=list[ApproverInviteResponse])
    def list_approver_invites(
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> list[ApproverInviteResponse]:
        return svc.list_approver_invites()

    @router.post("/operator/approver-invites", response_model=ApproverInviteResponse)
    def create_approver_invite(
        payload: ApproverInviteCreateRequest,
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> ApproverInviteResponse:
        return svc.create_approver_invite(payload)

    @router.get("/operator/producers", response_model=list[ProducerResponse])
    def list_producers(principal=Depends(_require_admin), svc: ClawPassService = Depends(service)) -> list[ProducerResponse]:
        return svc.list_producers()

    @router.post("/operator/producers", response_model=ProducerResponse)
    def create_producer(
        payload: ProducerCreateRequest,
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> ProducerResponse:
        return svc.create_producer(payload)

    @router.post("/operator/producers/{producer_id}/keys", response_model=ProducerKeyResponse)
    def issue_producer_key(
        producer_id: str,
        payload: ProducerKeyCreateRequest,
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> ProducerKeyResponse:
        return svc.issue_producer_key(producer_id, payload)

    @router.post("/operator/producers/{producer_id}/keys/{key_id}/revoke", response_model=ProducerKeyResponse)
    def revoke_producer_key(
        producer_id: str,
        key_id: str,
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> ProducerKeyResponse:
        return svc.revoke_producer_key(producer_id, key_id)

    @router.post("/approval-requests", response_model=ApprovalRequestResponse)
    def create_approval_request(
        payload: CreateApprovalRequest,
        authorization: str | None = Header(default=None, alias="Authorization"),
        svc: ClawPassService = Depends(service),
    ) -> ApprovalRequestResponse:
        producer = svc.require_producer(authorization)
        return svc.create_approval_request(payload, producer_id=producer.producer_id)

    @router.get("/approval-requests", response_model=list[ApprovalRequestResponse])
    def list_approval_requests(
        request: Request,
        status: str | None = Query(default=None),
        authorization: str | None = Header(default=None, alias="Authorization"),
        svc: ClawPassService = Depends(service),
    ) -> list[ApprovalRequestResponse]:
        admin = svc.resolve_admin_session(_session_cookie(request))
        if admin:
            return svc.list_approval_requests(status=status)
        producer = svc.require_producer(authorization)
        return svc.list_approval_requests(status=status, producer_id=producer.producer_id)

    @router.get("/approval-requests/{request_id}", response_model=ApprovalRequestResponse)
    def get_approval_request(
        request_id: str,
        request: Request,
        authorization: str | None = Header(default=None, alias="Authorization"),
        svc: ClawPassService = Depends(service),
    ) -> ApprovalRequestResponse:
        human = svc.resolve_human_session(_session_cookie(request))
        if human:
            return svc.get_approval_request(request_id)
        producer = svc.require_producer(authorization)
        return svc.get_approval_request(request_id, producer_id=producer.producer_id)

    @router.post("/approval-requests/{request_id}/cancel", response_model=ApprovalRequestResponse)
    def cancel_approval_request(
        request_id: str,
        payload: CancelApprovalRequest,
        request: Request,
        authorization: str | None = Header(default=None, alias="Authorization"),
        csrf_header: str | None = Header(default=None, alias="X-ClawPass-CSRF"),
        svc: ClawPassService = Depends(service),
    ) -> ApprovalRequestResponse:
        admin = svc.resolve_admin_session(
            _session_cookie(request),
            csrf_token=csrf_header,
            require_csrf=True,
        )
        if admin:
            return svc.cancel_approval_request(request_id, reason=payload.reason, actor=admin.admin_id)
        producer = svc.require_producer(authorization)
        return svc.cancel_approval_request(
            request_id,
            reason=payload.reason,
            actor=producer.producer_id,
            producer_id=producer.producer_id,
        )

    @router.post("/approval-requests/{request_id}/decision/start", response_model=DecisionStartResponse)
    def start_decision(
        request_id: str,
        payload: DecisionStartRequest,
        principal=Depends(_require_human),
        svc: ClawPassService = Depends(service),
    ) -> DecisionStartResponse:
        return svc.start_decision(
            request_id,
            DecisionStartRequest(
                approver_id=principal.approver_id,
                decision=payload.decision,
                method=payload.method,
            ),
        )

    @router.post("/approval-requests/{request_id}/decision/complete", response_model=DecisionCompleteResponse)
    def complete_decision(
        request_id: str,
        payload: DecisionCompleteRequest,
        principal=Depends(_require_human),
        svc: ClawPassService = Depends(service),
    ) -> DecisionCompleteResponse:
        request_model = svc.complete_decision(request_id, payload)
        return DecisionCompleteResponse(request=request_model)

    @router.get("/approvers/{approver_id}/summary", response_model=ApproverSummary)
    def approver_summary(
        approver_id: str,
        principal=Depends(_require_human),
        svc: ClawPassService = Depends(service),
    ) -> ApproverSummary:
        if not principal.is_admin and principal.approver_id != approver_id:
            raise HTTPException(status_code=403, detail="Cannot inspect another approver without admin access.")
        return svc.get_approver_summary(approver_id)

    @router.get("/webhook-events", response_model=list[WebhookEventResponse])
    def webhook_events(
        request_id: str | None = Query(default=None),
        status: str | None = Query(default=None),
        event_type: str | None = Query(default=None),
        callback_url: str | None = Query(default=None),
        limit: int = Query(default=200, ge=1, le=200),
        cursor: str | None = Query(default=None),
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> list[WebhookEventResponse]:
        return svc.list_webhook_events(
            request_id=request_id,
            status=status,
            event_type=event_type,
            callback_url=callback_url,
            limit=limit,
            cursor=cursor,
        )

    @router.get("/webhook-summary", response_model=WebhookDeliverySummary)
    def webhook_summary(principal=Depends(_require_admin), svc: ClawPassService = Depends(service)) -> WebhookDeliverySummary:
        return svc.get_webhook_delivery_summary()

    @router.get("/webhook-endpoints/summary", response_model=list[WebhookEndpointSummary])
    def webhook_endpoint_summaries(
        limit: int = Query(default=20, ge=1, le=100),
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> list[WebhookEndpointSummary]:
        return svc.list_webhook_endpoint_summaries(limit=limit)

    @router.post("/webhook-endpoints/mute", response_model=WebhookEndpointControlResponse)
    def mute_webhook_endpoint(
        payload: WebhookEndpointMuteRequest,
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> WebhookEndpointControlResponse:
        return svc.mute_webhook_endpoint(payload, actor=principal.admin_id)

    @router.post("/webhook-endpoints/unmute", response_model=WebhookEndpointControlResponse)
    def unmute_webhook_endpoint(
        payload: WebhookEndpointUnmuteRequest,
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> WebhookEndpointControlResponse:
        return svc.unmute_webhook_endpoint(payload, actor=principal.admin_id)

    @router.post("/webhook-events/prune", response_model=WebhookPruneResult)
    def prune_webhook_events(principal=Depends(_require_admin), svc: ClawPassService = Depends(service)) -> WebhookPruneResult:
        return svc.prune_webhook_history(emit_audit=True, actor=principal.admin_id)

    @router.get("/webhook-prune-history", response_model=list[WebhookPruneHistoryEntry])
    def webhook_prune_history(
        limit: int = Query(default=20, ge=1, le=100),
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> list[WebhookPruneHistoryEntry]:
        return svc.list_webhook_prune_history(limit=limit)

    @router.post("/webhook-events/{event_id}/redeliver", response_model=WebhookEventResponse)
    def redeliver_webhook_event(
        event_id: str,
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> WebhookEventResponse:
        return svc.redeliver_webhook_event(event_id)

    @router.post("/webhook-events/{event_id}/retry-now", response_model=WebhookEventResponse)
    def retry_webhook_event_now(
        event_id: str,
        principal=Depends(_require_admin),
        svc: ClawPassService = Depends(service),
    ) -> WebhookEventResponse:
        return svc.retry_webhook_event_now(event_id)

    return router
