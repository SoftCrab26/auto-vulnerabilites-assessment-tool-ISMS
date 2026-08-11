from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Form, Request
from fastapi.responses import RedirectResponse
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from app.config import ADMIN_PASSWORD, ADMIN_USER
from app.db import SessionLocal, get_db
from app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def seed_admin_user() -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == ADMIN_USER).first()
        if user is None:
            db.add(User(username=ADMIN_USER, password_hash=hash_password(ADMIN_PASSWORD)))
            db.commit()
    finally:
        db.close()


def get_current_username(request: Request) -> str | None:
    return request.session.get("user")


def require_login(request: Request) -> str | RedirectResponse:
    user = get_current_username(request)
    if not user:
        return RedirectResponse(url="/login", status_code=HTTP_303_SEE_OTHER)
    return user


def login_user(db: Session, username: str, password: str) -> bool:
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        return False
    return verify_password(password, user.password_hash)


DbDep = Annotated[Session, Depends(get_db)]


async def handle_login(
    request: Request,
    db: DbDep,
    username: str = Form(...),
    password: str = Form(...),
):
    if login_user(db, username.strip(), password):
        request.session["user"] = username.strip()
        return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)
    return False
