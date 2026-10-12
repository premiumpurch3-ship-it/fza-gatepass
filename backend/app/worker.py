"""Background worker: e-mail outbox, return reminders, attachment hashing jobs, housekeeping, nightly audit-chain verification.
Run:  python -m app.worker   (one process; safe to run several thanks to SKIP LOCKED)"""
import logging
import time
from datetime import datetime, timezone

from .core.db import one, q, rows, tx
from .services import attachments, notifications, workflow

log = logging.getLogger("worker")


def process_jobs(limit=10):
    done = 0
    with tx() as c:
        jobs = rows(c, """SELECT id, job_type, payload, attempts, max_attempts FROM background_jobs WHERE status = 'PENDING' AND run_at <= now()
                          ORDER BY run_at LIMIT :l FOR UPDATE SKIP LOCKED""", l=limit)
        for j in jobs:
            try:
                if j["job_type"] == "attachment.hash":
                    attachments.process_hash_job(j["payload"]["attachment_id"])
                q(c, "UPDATE background_jobs SET status = 'DONE', finished_at = now(), attempts = attempts + 1 WHERE id = :i", i=j["id"])
                done += 1
            except Exception as e:
                dead = j["attempts"] + 1 >= j["max_attempts"]
                q(c, "UPDATE background_jobs SET status = :s, attempts = attempts + 1, last_error = :e, run_at = now() + interval '5 minutes' WHERE id = :i",
                  s="DEAD" if dead else "PENDING", e=str(e)[:300], i=j["id"])
    return done


def housekeeping():
    with tx() as c:
        q(c, "DELETE FROM idempotency_keys WHERE expires_at < now()")
        q(c, "DELETE FROM auth_sessions WHERE expires_at < now() - interval '30 days'")
        # abandoned uploads: pending for > 24h
        q(c, "UPDATE gate_pass_attachments SET status = 'DELETED', deleted_at = now(), delete_reason = 'abandoned upload' WHERE status = 'PENDING_UPLOAD' AND created_at < now() - interval '24 hours'")


def verify_audit_chain():
    with tx() as c:
        r = rows(c, "SELECT * FROM audit_verify_chain(0)")[0]
        q(c, "INSERT INTO audit_chain_checks (rows_checked, ok, first_bad_audit_id, details) VALUES (:n, :ok, :b, 'nightly check')", n=r["rows_checked"], ok=r["first_bad"] is None, b=r["first_bad"])
        if r["first_bad"] is not None:
            log.error("AUDIT CHAIN BROKEN at id %s", r["first_bad"])


def main():
    logging.basicConfig(level=logging.INFO)
    last = {"rem": 0, "house": 0, "audit": ""}
    log.info("worker started")
    while True:
        try:
            notifications.send_pending_emails()
            process_jobs()
            now = time.monotonic()
            if now - last["rem"] > 3600:
                n = workflow.run_reminders()
                last["rem"] = now
                if n:
                    log.info("sent %s return reminders", n)
            if now - last["house"] > 900:
                housekeeping(); last["house"] = now
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            if last["audit"] != day and datetime.now(timezone.utc).hour == 21:   # ~02:00 Asia/Karachi
                verify_audit_chain(); last["audit"] = day
        except Exception:
            log.exception("worker loop error")
        time.sleep(10)


if __name__ == "__main__":
    main()
