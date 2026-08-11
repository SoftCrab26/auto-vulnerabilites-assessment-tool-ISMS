from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("WEB_DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
EXPORT_DIR = DATA_DIR / "exports"
DB_PATH = DATA_DIR / "app.db"
GUIDELINES_SEED = BASE_DIR / "templates_excel" / "guidelines.json"
EXCEL_TEMPLATE_DIR = BASE_DIR / "templates_excel"

SECRET_KEY = os.getenv("WEB_SECRET_KEY", "change-me-in-production-isms-web")
ADMIN_USER = os.getenv("WEB_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("WEB_ADMIN_PASSWORD", "admin")
SESSION_MAX_AGE = int(os.getenv("WEB_SESSION_MAX_AGE", "86400"))
MAX_UPLOAD_BYTES = int(os.getenv("WEB_MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))


def ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
