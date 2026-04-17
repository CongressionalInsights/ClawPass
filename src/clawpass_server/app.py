from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from clawpass_server.adapters.ethereum_adapter import EthereumAdapter
from clawpass_server.adapters.webauthn_adapter import WebAuthnAdapter
from clawpass_server.api.routes import get_router
from clawpass_server.core.config import Settings, load_settings
from clawpass_server.core.database import Database
from clawpass_server.core.service import ClawPassService


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.db_path)
    db.ensure_ready()

    webauthn = WebAuthnAdapter(settings)
    ethereum = EthereumAdapter()
    service = ClawPassService(settings=settings, db=db, webauthn=webauthn, ethereum=ethereum)
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
    def index() -> FileResponse:
        return FileResponse(web_root / "index.html")

    return app
