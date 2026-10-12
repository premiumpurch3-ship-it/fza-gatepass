"""Per-request context used by audit/approval evidence (IP, device, user)."""
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class ReqCtx:
    request_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    platform: str | None = None
    client_version: str | None = None
    user_id: str | None = None
    username: str | None = None
    session_id: str | None = None
    is_master_admin: bool = False
    perms: set = field(default_factory=set)


_ctx: ContextVar[ReqCtx] = ContextVar("reqctx", default=ReqCtx())


def get() -> ReqCtx:
    return _ctx.get()


def set_(c: ReqCtx):
    return _ctx.set(c)
