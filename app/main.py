"""FastAPI application factory — Phase 2.

Adds auth middleware, Chart.js in templates, batch/metics routes.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routes import views, api
from app.middleware import AuthMiddleware
from app.db import run_init_sql


def create_app() -> FastAPI:
    app = FastAPI(title="Contextual Vulnerability Risk Scoring", version="0.2.0")

    # Auth middleware (no-op when APP_API_KEY is empty)
    app.add_middleware(AuthMiddleware)

    # Static files
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Startup: ensure DB schema is ready
    @app.on_event("startup")
    def _startup() -> None:
        run_init_sql()

    # Routers
    app.include_router(views.router)
    app.include_router(api.router)

    return app


app = create_app()
