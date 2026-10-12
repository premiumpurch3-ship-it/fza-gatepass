from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from ..core import deps
from ..core.config import settings
from ..core.errors import AppError
from ..services import auth as svc

router = APIRouter(prefix="/auth", tags=["auth"])
COOKIE = "gp_rt"


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)
    totp: str | None = None
    recovery_code: str | None = None


class RefreshIn(BaseModel):
    refresh_token: str | None = None


class PwIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=1, max_length=200)


def _set_cookie(resp: Response, data: dict, platform: str):
    """Web: refresh token travels in an HttpOnly cookie scoped to /api/v1/auth. Shells keep it in secure storage (returned in body)."""
    if platform == "web" and data.get("refresh_token"):
        resp.set_cookie(COOKIE, data["refresh_token"], httponly=True, secure=settings.env == "production", samesite="strict",
                        path="/api/v1/auth", max_age=settings.refresh_token_days * 86400)
        data = {k: v for k, v in data.items() if k != "refresh_token"}
        data["refresh_in_cookie"] = True
    return data


@router.post("/login")
def login(body: LoginIn, response: Response, request: Request):
    data = svc.login(body.username, body.password, body.totp, body.recovery_code)
    return _set_cookie(response, data, request.headers.get("x-client-platform", "web").lower())


@router.post("/refresh")
def refresh(request: Request, response: Response, body: RefreshIn | None = None):
    plat = request.headers.get("x-client-platform", "web").lower()
    tok = (body.refresh_token if body else None) or request.cookies.get(COOKIE)
    if tok and request.cookies.get(COOKIE) and not (body and body.refresh_token):
        if request.headers.get("x-requested-with") != "fzagp":     # CSRF guard for the cookie flow
            raise AppError("CSRF", "Missing CSRF header", 403)
    if not tok:
        raise AppError("INVALID_REFRESH", "Session expired. Please sign in again.", 401)
    return _set_cookie(response, svc.refresh(tok), plat)


@router.post("/logout")
def logout(response: Response, user=Depends(deps.setup_or_full_user)):
    svc.logout(user)
    response.delete_cookie(COOKIE, path="/api/v1/auth")
    return {"ok": True}


@router.post("/logout-all")
def logout_all(response: Response, user=Depends(deps.current_user)):
    svc.logout(user, all_sessions=True)
    response.delete_cookie(COOKIE, path="/api/v1/auth")
    return {"ok": True}


@router.get("/me")
def me(user=Depends(deps.setup_or_full_user)):
    return {"id": user["id"], "username": user["username"], "full_name": user["full_name"], "email": user["email"],
            "is_master_admin": user["is_master_admin"], "permissions": sorted(user["perms"]), "mfa_enabled": user["mfa_enabled"],
            "must_change_password": user["must_change_password"], "scope": user["scope"], "department_id": user["department_id"]}


@router.post("/change-password")
def change_password(body: PwIn, user=Depends(deps.current_user)):
    svc.change_password(user, body.current_password, body.new_password)
    return {"ok": True}


@router.post("/mfa/setup")
def mfa_setup(user=Depends(deps.setup_or_full_user)):
    return svc.mfa_setup(user)


class CodeIn(BaseModel):
    code: str


@router.post("/mfa/verify")
def mfa_verify(body: CodeIn, user=Depends(deps.setup_or_full_user)):
    return svc.mfa_verify(user, body.code)


class PwOnly(BaseModel):
    password: str


@router.post("/mfa/disable")
def mfa_disable(body: PwOnly, user=Depends(deps.current_user)):
    svc.mfa_disable(user, body.password)
    return {"ok": True}


@router.get("/sessions")
def sessions(user=Depends(deps.current_user)):
    return svc.sessions(user)


@router.delete("/sessions/{session_id}")
def revoke(session_id: str, user=Depends(deps.current_user)):
    svc.revoke_session(user, session_id)
    return {"ok": True}
