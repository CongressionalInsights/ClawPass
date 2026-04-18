from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from clawpass_server.core.auth import ADMIN_SESSION_COOKIE, SESSION_COOKIE
from clawpass_server.adapters.ethereum_adapter import EthereumAdapter
from clawpass_server.adapters.webauthn_adapter import WebAuthnAdapter
from clawpass_server.api.routes import get_router
from clawpass_server.core.config import Settings, load_settings, validate_settings
from clawpass_server.core.database import Database
from clawpass_server.core.service import ClawPassService


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.db_path)
    db.ensure_ready()

    webauthn = WebAuthnAdapter(settings)
    ethereum = EthereumAdapter()
    service = ClawPassService(settings=settings, db=db, webauthn=webauthn, ethereum=ethereum)
    validate_settings(settings, initialized=service.is_initialized())
    service.recover_queued_webhook_events()
    service.prune_webhook_history()
    service.start_webhook_recovery_loop()

    app = FastAPI(
        title="ClawPass",
        version="0.1.0",
        description="Dual-mode approval platform with first-class passkey onboarding.",
    )

    def get_service() -> ClawPassService:
        return service

    app.include_router(get_router(get_service))

    web_root = Path(__file__).resolve().parent / "web"
    app.mount("/assets", StaticFiles(directory=web_root), name="assets")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/")
    def index(request: Request):
        if not service.is_initialized():
            return RedirectResponse("/setup", status_code=302)
        session_id = request.cookies.get(SESSION_COOKIE) or request.cookies.get(ADMIN_SESSION_COOKIE)
        principal = service.resolve_human_session(session_id)
        if principal and principal.is_admin:
            return RedirectResponse("/app", status_code=302)
        return RedirectResponse("/login", status_code=302)

    @app.get("/setup")
    def setup_page(request: Request):
        if service.is_initialized():
            session_id = request.cookies.get(SESSION_COOKIE) or request.cookies.get(ADMIN_SESSION_COOKIE)
            principal = service.resolve_human_session(session_id)
            return RedirectResponse("/app" if principal and principal.is_admin else "/login", status_code=302)
        return FileResponse(web_root / "setup.html")

    @app.get("/login")
    def login_page(request: Request):
        if not service.is_initialized():
            return RedirectResponse("/setup", status_code=302)
        next_path = request.query_params.get("next")
        session_id = request.cookies.get(SESSION_COOKIE) or request.cookies.get(ADMIN_SESSION_COOKIE)
        principal = service.resolve_human_session(session_id)
        if principal:
            if next_path:
                return RedirectResponse(next_path, status_code=302)
            if principal.is_admin:
                return RedirectResponse("/app", status_code=302)
        return FileResponse(web_root / "login.html")

    @app.get("/app")
    def app_page(request: Request):
        if not service.is_initialized():
            return RedirectResponse("/setup", status_code=302)
        session_id = request.cookies.get(SESSION_COOKIE) or request.cookies.get(ADMIN_SESSION_COOKIE)
        principal = service.resolve_human_session(session_id)
        if not principal or not principal.is_admin:
            return RedirectResponse("/login", status_code=302)
        return FileResponse(web_root / "index.html")

    @app.get("/approve/{request_id}")
    def approval_page(request_id: str) -> FileResponse:
        return FileResponse(web_root / "approve.html")

    @app.get("/invites/{token}")
    def invite_page(token: str) -> FileResponse:
        return FileResponse(web_root / "invite.html")

    return app
