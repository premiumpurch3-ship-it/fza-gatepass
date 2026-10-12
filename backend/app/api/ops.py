import asyncio
from datetime import date

import jwt
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from ..core import deps
from ..core.audit import audit
from ..core.config import settings
from ..core.db import rows, scalar, tx
from ..core.errors import AppError, Forbidden, NotFound
from ..core.idem import IdempotentRoute
from ..core.paging import Page
from ..services import attachments as att, notifications as nt, reports, workflow as wf
from ..storage import get_storage

U = Depends(deps.current_user)

# ---------- approvals / security / returns ----------
workflow = APIRouter(tags=["workflow"], route_class=IdempotentRoute)


@workflow.get("/approvals/pending")
def pending(pg: Page = Depends(), user=U):
    return wf.pending_queue(user, pg)


@workflow.get("/security/awaiting-out")
def awaiting_out(pg: Page = Depends(), q: str | None = Query(None, max_length=60), user=U):
    return wf.security_queue(user, pg, "out", q)


@workflow.get("/security/awaiting-in")
def awaiting_in(pg: Page = Depends(), q: str | None = Query(None, max_length=60), user=U):
    return wf.security_queue(user, pg, "in", q)


@workflow.get("/security/gates")
def gates(user=Depends(deps.require("security.gateout", "security.gatein", any_of=True))):
    with tx() as c:
        return rows(c, "SELECT id, code, name FROM gates WHERE is_active ORDER BY name")


@workflow.get("/returns")
def returns(pg: Page = Depends(), user=U, status: str | None = None, overdue: bool | None = None, outstanding: bool | None = None, location_id: str | None = None,
            responsible_user_id: str | None = None, q: str | None = Query(None, max_length=100), date_from: date | None = None, date_to: date | None = None):
    return wf.returns_list(user, pg, dict(status=status, overdue=overdue, outstanding=outstanding, location_id=location_id, responsible_user_id=responsible_user_id,
                                          q=q, date_from=date_from, date_to=date_to))


@workflow.get("/returns/{record_id}")
def return_detail(record_id: str, user=U):
    return wf.return_detail(user, record_id)


class ReasonIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


@workflow.post("/returns/transactions/{txn_id}/reverse")
def reverse(txn_id: str, body: ReasonIn, user=U):
    return wf.reverse(user, txn_id, body.reason)


# ---------- attachments ----------
attachments = APIRouter(tags=["attachments"], route_class=IdempotentRoute)


@attachments.post("/attachments/{att_id}/confirm")
def confirm(att_id: str, user=U):
    return att.confirm(user, att_id)


@attachments.put("/attachments/{att_id}/content")
async def proxy_upload(att_id: str, request: Request, user=U):
    data = await request.body()
    await asyncio.to_thread(att.upload_proxy, user, att_id, data, request.headers.get("content-type", ""))
    return {"ok": True}


@attachments.get("/attachments/{att_id}/download")
def download(att_id: str, user=U):
    return att.download(user, att_id)


@attachments.get("/attachments/{att_id}/thumbnail")
def thumbnail(att_id: str, user=U):
    return att.download(user, att_id, thumbnail=True)


class DelIn(BaseModel):
    reason: str = Field(min_length=1, max_length=300)


@attachments.post("/attachments/{att_id}/delete")
def delete(att_id: str, body: DelIn, user=U):
    att.delete(user, att_id, body.reason)
    return {"ok": True}


# local-storage presigned endpoints (dev / single-server deployments without S3). Authorised by a signed, expiring, key-bound token.
local = APIRouter(tags=["storage"])


def _tok(token: str, method: str) -> dict:
    try:
        t = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise AppError("INVALID_TOKEN", "Link expired or invalid", 403)
    if t.get("m") != method:
        raise AppError("INVALID_TOKEN", "Link expired or invalid", 403)
    return t


@local.put("/storage/local/{token}")
async def local_put(token: str, request: Request):
    t = _tok(token, "PUT")
    data = await request.body()
    if len(data) > t["mx"]:
        raise AppError("FILE_TOO_LARGE", "File is too large", 413)
    get_storage().put_bytes(t["k"], data, t.get("ct", "application/octet-stream"))
    return Response(status_code=200)


@local.get("/storage/local/{token}")
def local_get(token: str):
    t = _tok(token, "GET")
    p = get_storage()._path(t["k"])
    if not p.exists():
        raise NotFound("File")
    disp = f"{'inline' if t.get('il') else 'attachment'}; filename*=UTF-8''{t['fn']}"
    from urllib.parse import quote
    return FileResponse(p, media_type=t.get("ct", "application/octet-stream"), headers={"Content-Disposition": f"{'inline' if t.get('il') else 'attachment'}; filename*=UTF-8''{quote(t['fn'])}", "Cache-Control": "private, no-store"})


# ---------- notifications ----------
notif = APIRouter(prefix="/notifications", tags=["notifications"])


@notif.get("")
def inbox(pg: Page = Depends(), unread_only: bool = False, user=U):
    return nt.inbox(user, pg, unread_only)


@notif.post("/read-all")
def read_all(user=U):
    nt.mark_read(user)
    return {"ok": True}


@notif.post("/{nid}/read")
def read(nid: str, user=U):
    nt.mark_read(user, nid)
    return {"ok": True}


class PrefIn(BaseModel):
    event_type: str
    in_app: bool | None = None
    email: bool | None = None


@notif.get("/preferences")
def prefs(user=U):
    return nt.get_prefs(user)


@notif.put("/preferences")
def put_prefs(body: list[PrefIn], user=U):
    nt.put_prefs(user, [p.model_dump(exclude_unset=True) for p in body])
    return {"ok": True}


# ---------- reports / dashboard / audit ----------
rep = APIRouter(tags=["reports"])


@rep.get("/reports")
def catalogue(user=Depends(deps.require("reports.view", "audit.view", any_of=True))):
    return reports.catalogue(user)


def _rf(date_from, date_to, location_id, status, returnable, created_by):
    return dict(date_from=date_from, date_to=date_to, location_id=location_id, status=status, returnable=returnable, created_by=created_by)


@rep.get("/reports/{code}")
def run_report(code: str, pg: Page = Depends(), date_from: date | None = None, date_to: date | None = None, location_id: str | None = None,
               status: str | None = None, returnable: bool | None = None, created_by: str | None = None, user=U):
    return reports.run(user, code, _rf(date_from, date_to, location_id, status, returnable, created_by), pg)


@rep.get("/reports/{code}/export")
def export_report(code: str, format: str = Query("csv", pattern="^(csv|xlsx|pdf)$"), date_from: date | None = None, date_to: date | None = None,
                  location_id: str | None = None, status: str | None = None, returnable: bool | None = None, created_by: str | None = None, user=U):
    data, mime, name = reports.export(user, code, _rf(date_from, date_to, location_id, status, returnable, created_by), format)
    return Response(data, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})


@rep.get("/dashboard/summary")
def dashboard(user=Depends(deps.require("dashboard.view")), date_from: date | None = None, date_to: date | None = None, location_id: str | None = None,
              status: str | None = None, type: str | None = None, returnable: bool | None = None, responsible_user_id: str | None = None):
    return reports.dashboard(user, dict(date_from=date_from, date_to=date_to, location_id=location_id, status=status, type=type, returnable=returnable,
                                        responsible_user_id=responsible_user_id))


audit_r = APIRouter(prefix="/audit-logs", tags=["audit"])


@audit_r.get("")
def audit_list(pg: Page = Depends(), user=Depends(deps.require("audit.view")), q: str | None = Query(None, max_length=100), action: str | None = None,
               entity_type: str | None = None, actor: str | None = None, gate_pass_id: str | None = None, severity: str | None = None,
               date_from: date | None = None, date_to: date | None = None):
    from ..core.paging import envelope
    where, p = ["TRUE"], {}
    if q:
        where.append("(a.summary ILIKE :q OR a.entity_id ILIKE :q OR a.actor_username ILIKE :q)"); p["q"] = f"%{q}%"
    for k, col in (("action", "a.action"), ("entity_type", "a.entity_type"), ("severity", "a.severity")):
        v = locals()[k]
        if v:
            where.append(f"{col} = :{k}"); p[k] = v
    if actor:
        where.append("a.actor_username = :actor"); p["actor"] = actor
    if gate_pass_id:
        where.append("a.gate_pass_id = CAST(:gp AS uuid)"); p["gp"] = gate_pass_id
    if date_from:
        where.append("(a.occurred_at AT TIME ZONE :tz)::date >= :df"); p["df"] = date_from; p["tz"] = settings.timezone
    if date_to:
        where.append("(a.occurred_at AT TIME ZONE :tz)::date <= :dt"); p["dt"] = date_to; p["tz"] = settings.timezone
    W = " AND ".join(where)
    with tx() as c:
        total = scalar(c, f"SELECT count(*) FROM audit_logs a WHERE {W}", **p)
        items = rows(c, f"""SELECT a.id, a.occurred_at, a.actor_username, a.action, a.entity_type, a.entity_id, a.gate_pass_id, a.severity, a.summary, a.before, a.after,
                            a.ip::text AS ip, a.platform, a.client_version FROM audit_logs a WHERE {W} ORDER BY a.id DESC LIMIT :l OFFSET :o""", l=pg.size, o=pg.offset, **p)
        return envelope(items, total, pg)


@audit_r.get("/verify-chain")
def verify_chain(user=Depends(deps.require("audit.view"))):
    with tx() as c:
        r = rows(c, "SELECT * FROM audit_verify_chain(0)")[0]
        ok = r["first_bad"] is None
        c.exec_driver_sql("INSERT INTO audit_chain_checks (rows_checked, ok, first_bad_audit_id, details) VALUES (%s, %s, %s, %s)",
                          (r["rows_checked"], ok, r["first_bad"], "manual verification"))
        return {"ok": ok, "rows_checked": r["rows_checked"], "first_bad_audit_id": r["first_bad"]}
