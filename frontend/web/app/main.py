from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth import seed_admin_user
from app.config import SECRET_KEY, SESSION_MAX_AGE, ensure_directories
from app.db import SessionLocal, init_db
from app.routers import auth_routes, export, pages
from app.services.guidelines import seed_guidelines

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="ISMS-P Analyzer", docs_url=None, redoc_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    max_age=SESSION_MAX_AGE,
    same_site="lax",
    https_only=False,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(auth_routes.router)
app.include_router(pages.router)
app.include_router(export.router)


@app.on_event("startup")
def on_startup() -> None:
    ensure_directories()
    init_db()
    seed_admin_user()
    db = SessionLocal()
    try:
        seed_guidelines(db)
    finally:
        db.close()
