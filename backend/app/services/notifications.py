"""Outbox-based notifications. Rows are written in the business transaction (so they never fail it); the worker sends e-mails
asynchronously with retry/backoff. Channels are pluggable (IN_APP, EMAIL now; WHATSAPP/SMS reserved in the schema)."""
import smtplib
from email.message import EmailMessage

from ..core import settings_store as ss
from ..core.config import settings
from ..core.db import J, one, q, rows, tx
from ..core.errors import NotFound
from ..core.paging import Page, envelope

EVENTS = {"approval_required": "Approval required", "approval_completed": "Approval completed", "rejected": "Gate pass rejected",
          "approved": "Gate pass approved", "gate_out": "Gate Out recorded", "gate_in": "Gate In recorded", "return_due": "Return due",
          "return_overdue": "Return overdue", "closed_writeoff": "Return closed / written off", "cancelled": "Gate pass cancelled"}


def holders_of(c, perm: str) -> list[str]:
    return [str(r["id"]) for r in rows(c, """
        SELECT u.id FROM users u WHERE u.is_active AND (u.is_master_admin OR (
          (EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id AND r.is_active JOIN role_permissions rp ON rp.role_id = r.id
                   WHERE ur.user_id = u.id AND rp.permission_code = :p)
           OR EXISTS (SELECT 1 FROM user_permissions up WHERE up.user_id = u.id AND up.permission_code = :p AND up.effect = 'GRANT'))
          AND NOT EXISTS (SELECT 1 FROM user_permissions up WHERE up.user_id = u.id AND up.permission_code = :p AND up.effect = 'DENY')))""", p=perm)]


def notify(c, user_ids, event: str, title: str, body: str, gate_pass_id=None, payload: dict | None = None, dedupe: str = "", exclude=None):
    email_on = ss.get("notifications.email_enabled", c)
    for uid in {str(u) for u in user_ids} - {str(exclude)} if exclude else {str(u) for u in user_ids}:
        pref = {(r["channel"]): r["enabled"] for r in rows(c, "SELECT channel, enabled FROM notification_preferences WHERE user_id = :u AND event_type = :e", u=uid, e=event)}
        u = one(c, "SELECT email, is_active FROM users WHERE id = :u", u=uid)
        if not u or not u["is_active"]:
            continue
        if pref.get("IN_APP", True):
            q(c, """INSERT INTO notifications (recipient_user_id, channel, event_type, gate_pass_id, title, body, payload, status, sent_at, dedupe_key)
                    VALUES (:u, 'IN_APP', :e, :g, :t, :b, CAST(:p AS jsonb), 'SENT', now(), :d) ON CONFLICT (dedupe_key) DO NOTHING""",
              u=uid, e=event, g=gate_pass_id, t=title, b=body, p=J(payload or {}), d=f"{dedupe}:{uid}:IN_APP")
        if email_on and u["email"] and pref.get("EMAIL", True):
            q(c, """INSERT INTO notifications (recipient_user_id, channel, event_type, gate_pass_id, title, body, payload, status, next_attempt_at, dedupe_key)
                    VALUES (:u, 'EMAIL', :e, :g, :t, :b, CAST(:p AS jsonb), 'PENDING', now(), :d) ON CONFLICT (dedupe_key) DO NOTHING""",
              u=uid, e=event, g=gate_pass_id, t=title, b=body, p=J(payload or {}), d=f"{dedupe}:{uid}:EMAIL")


def inbox(user, pg: Page, unread_only=False):
    with tx() as c:
        w = "recipient_user_id = :u AND channel = 'IN_APP'" + (" AND read_at IS NULL" if unread_only else "")
        total = one(c, f"SELECT count(*) AS n FROM notifications WHERE {w}", u=user["id"])["n"]
        items = rows(c, f"""SELECT id, event_type, gate_pass_id, title, body, created_at, read_at FROM notifications WHERE {w}
                            ORDER BY created_at DESC LIMIT :l OFFSET :o""", u=user["id"], l=pg.size, o=pg.offset)
        unread = one(c, "SELECT count(*) AS n FROM notifications WHERE recipient_user_id = :u AND channel = 'IN_APP' AND read_at IS NULL", u=user["id"])["n"]
        return {**envelope(items, total, pg), "unread": unread}


def mark_read(user, nid=None):
    with tx() as c:
        if nid:
            if not one(c, "UPDATE notifications SET read_at = now(), status = 'READ' WHERE id = :i AND recipient_user_id = :u RETURNING id", i=nid, u=user["id"]):
                raise NotFound("Notification")
        else:
            q(c, "UPDATE notifications SET read_at = now(), status = 'READ' WHERE recipient_user_id = :u AND channel = 'IN_APP' AND read_at IS NULL", u=user["id"])


def get_prefs(user):
    with tx() as c:
        saved = {(r["event_type"], r["channel"]): r["enabled"] for r in rows(c, "SELECT * FROM notification_preferences WHERE user_id = :u", u=user["id"])}
        return [{"event_type": e, "label": lbl, "in_app": saved.get((e, "IN_APP"), True), "email": saved.get((e, "EMAIL"), True)} for e, lbl in EVENTS.items()]


def put_prefs(user, prefs: list[dict]):
    with tx() as c:
        for p in prefs:
            if p["event_type"] not in EVENTS:
                continue
            for ch, k in (("IN_APP", "in_app"), ("EMAIL", "email")):
                if k in p:
                    q(c, """INSERT INTO notification_preferences (user_id, event_type, channel, enabled) VALUES (:u, :e, :c, :v)
                            ON CONFLICT (user_id, event_type, channel) DO UPDATE SET enabled = :v""", u=user["id"], e=p["event_type"], c=ch, v=bool(p[k]))


def send_pending_emails(limit=50) -> dict:
    """Worker entry point. Claims rows with SKIP LOCKED so several workers can run; failures are retried with backoff."""
    sent = failed = 0
    with tx() as c:
        batch = rows(c, """SELECT n.id, n.title, n.body, n.attempts, u.email, u.full_name FROM notifications n JOIN users u ON u.id = n.recipient_user_id
                           WHERE n.channel = 'EMAIL' AND n.status = 'PENDING' AND n.next_attempt_at <= now()
                           ORDER BY n.next_attempt_at LIMIT :l FOR UPDATE OF n SKIP LOCKED""", l=limit)
        for n in batch:
            try:
                _send_email(n["email"], n["title"], f"Hello {n['full_name']},\n\n{n['body']}\n\n— FZA-GatePass-MTJ")
                q(c, "UPDATE notifications SET status = 'SENT', sent_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = :i", i=n["id"])
                sent += 1
            except Exception as e:  # never raises into business flows
                att = n["attempts"] + 1
                dead = att >= 6
                q(c, """UPDATE notifications SET attempts = :a, last_error = :e, status = :s,
                        next_attempt_at = now() + (interval '1 minute' * power(3, :a)) WHERE id = :i""",
                  a=att, e=str(e)[:300], s="FAILED" if dead else "PENDING", i=n["id"])
                failed += 1
    return {"sent": sent, "failed": failed}


def _send_email(to: str, subject: str, body: str):
    if not settings.smtp_host:
        raise RuntimeError("SMTP is not configured")
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = settings.smtp_from, to, subject
    m.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
        if settings.smtp_starttls:
            s.starttls()
        if settings.smtp_user:
            s.login(settings.smtp_user, settings.smtp_password or "")
        s.send_message(m)
