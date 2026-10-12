import uuid
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError

from . import ctx, rbac
from .config import settings
from .db import one, tx
from .errors import AppError, Forbidden
from .security import decode_access_token

bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str | None:
    import ipaddress
    raw = None
    if settings.env == "production":      # trusted proxy (Nginx) sets X-Forwarded-For
        xff = request.headers.get("x-forwarded-for")
        if xff:
            raw = xff.split(",")[0].strip()
    raw = raw or (request.client.host if request.client else None)
    try:
        return str(ipaddress.ip_address(raw)) if raw else None
    except ValueError:
        return None


async def request_context_middleware(request: Request, call_next):
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    try:
        uuid.UUID(rid)
    except ValueError:
        rid = str(uuid.uuid4())
    request.state.request_id = rid
    plat = (request.headers.get("x-client-platform") or "web").lower()
    c = ctx.ReqCtx(request_id=rid, ip=client_ip(request), user_agent=request.headers.get("user-agent"),
                   platform=plat if plat in ("web", "electron", "android", "ios") else "web",
                   client_version=request.headers.get("x-client-version"))
    token = ctx.set_(c)
    try:
        resp = await call_next(request)
    finally:
        ctx._ctx.reset(token)
    resp.headers["X-Request-ID"] = rid
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Cache-Control"] = resp.headers.get("Cache-Control", "no-store")
    return resp


def _load_user(creds: HTTPAuthorizationCredentials | None, allow_setup: bool):
    if not creds:
        raise AppError("UNAUTHENTICATED", "Authentication required", 401)
    try:
        claims = decode_access_token(creds.credentials)
    except PyJWTError:
        raise AppError("INVALID_TOKEN", "Invalid or expired token", 401)
    if claims.get("scp", "full") != "full" and not allow_setup:
        raise AppError("MFA_SETUP_REQUIRED", "Multi-factor authentication setup is required", 403)
    with tx() as c:
        s = one(c, "SELECT id, revoked_at FROM auth_sessions WHERE id = :s AND user_id = :u", s=claims["sid"], u=claims["sub"])
        if not s or s["revoked_at"]:
            raise AppError("SESSION_REVOKED", "Session is no longer valid", 401)
        u = one(c, """SELECT id, username, full_name, email, is_active, is_master_admin, authz_version, must_change_password,
                             mfa_enabled, department_id FROM users WHERE id = :u""", u=claims["sub"])
        if not u or not u["is_active"]:
            raise AppError("USER_INACTIVE", "Account is not active", 401)
        u["perms"] = rbac.effective_permissions(c, u)
    u["session_id"] = claims["sid"]
    u["scope"] = claims.get("scp", "full")
    r = ctx.get()
    r.user_id, r.username, r.session_id, r.is_master_admin, r.perms = str(u["id"]), u["username"], claims["sid"], u["is_master_admin"], u["perms"]
    return u


async def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    return _load_user(creds, allow_setup=False)


async def setup_or_full_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    return _load_user(creds, allow_setup=True)


def require(*codes: str, any_of: bool = False):
    async def dep(user: dict = Depends(current_user)) -> dict:
        have = user["perms"]
        ok = any(c in have for c in codes) if any_of else all(c in have for c in codes)
        if not ok:
            raise Forbidden()
        return user
    return dep
