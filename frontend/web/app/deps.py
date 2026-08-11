from __future__ import annotations

from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_303_SEE_OTHER


def require_user(request: Request) -> str | RedirectResponse:
    user = request.session.get("user")
    if not user:
        return RedirectResponse("/login", status_code=HTTP_303_SEE_OTHER)
    return user
