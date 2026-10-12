"""Audit writer. Always called inside the caller's transaction so the audit row commits/rolls back with the change.
The hash chain is computed by a database trigger (see sql/0001_schema.sql), not by the application."""
import re
from . import ctx
from .db import J, q

_SECRET_KEYS = re.compile(r"(password|passwd|token|secret|mfa_secret|refresh|presigned|authorization)", re.I)


def scrub(o):
    if isinstance(o, dict):
        return {k: ("[REDACTED]" if _SECRET_KEYS.search(k) else scrub(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [scrub(v) for v in o]
    return o


def diff(before: dict | None, after: dict | None, keys: list[str] | None = None):
    """Changed fields only."""
    before, after = before or {}, after or {}
    ks = keys or sorted(set(before) | set(after))
    b, a = {}, {}
    for k in ks:
        if str(before.get(k)) != str(after.get(k)):
            b[k], a[k] = before.get(k), after.get(k)
    return b, a


def audit(c, action: str, entity_type: str, entity_id=None, summary: str = "", before=None, after=None,
          gate_pass_id=None, severity: str = "INFO", actor_id=None, actor_username=None):
    r = ctx.get()
    before, after = scrub(before) if before else None, scrub(after) if after else None
    q(c, """INSERT INTO audit_logs (actor_user_id, actor_username, action, entity_type, entity_id, gate_pass_id, severity, summary,
                                    before, after, ip, user_agent, platform, client_version, request_id, session_id, prev_hash, row_hash)
            VALUES (:actor, :uname, :action, :et, :eid, :gp, :sev, :summary, CAST(:before AS jsonb), CAST(:after AS jsonb),
                    CAST(:ip AS inet), :ua, :platform, :cv, CAST(:rid AS uuid), CAST(:sid AS uuid), decode('00','hex'), decode('00','hex'))""",
      actor=actor_id or r.user_id, uname=actor_username or r.username, action=action, et=entity_type,
      eid=None if entity_id is None else str(entity_id), gp=str(gate_pass_id) if gate_pass_id else None, sev=severity,
      summary=summary or action, before=J(before), after=J(after), ip=r.ip, ua=(r.user_agent or "")[:300] or None,
      platform=r.platform, cv=r.client_version, rid=r.request_id, sid=r.session_id)
