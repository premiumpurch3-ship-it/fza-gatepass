import csv
import io
import os
import socket
import subprocess
import sys
import time

import pytest
from openpyxl import load_workbook

from tests.conftest import gate_out, item, jpeg_bytes, new_outward, returned_inward, submitted_approved_outward, upload
from app.core.db import one, q, rows, tx


def test_dashboard_is_role_aware_and_comes_from_the_database(world):
    w = world
    out = submitted_approved_outward(w)
    new_outward(w)                                                                   # a second, still in draft
    d_sec = w.sec.get("/dashboard/summary").json()
    assert d_sec["pending_gate_out"] == 1 and "pending_approvals" not in d_sec and "active_users" not in d_sec
    d_app = w.a1.get("/dashboard/summary").json()
    assert "pending_gate_out" not in d_app and d_app["pending_approvals"] == 0
    d_creator = w.creator.get("/dashboard/summary").json()
    assert d_creator["my_drafts"] == 1 and "active_users" not in d_creator and "security_events_24h" not in d_creator
    gate_out(w, out["id"])
    returned_inward(w, out["id"], 4)
    d = w.audit.get("/dashboard/summary").json()
    assert d["total_outward"] == 1 and d["total_inward"] == 1 and d["outstanding_returnables"] == 1 and d["partially_returned"] == 1
    assert d["fully_returned"] == 0 and d["overdue_returnables"] == 0 and len(d["recent"]) == 2
    m = w.master.get("/dashboard/summary").json()
    assert m["active_users"] >= 1 and "security_events_24h" in m
    # filters
    assert w.audit.get("/dashboard/summary", params={"type": "INWARD"}).json()["total_outward"] == 0
    assert w.audit.get("/dashboard/summary", params={"returnable": False}).json()["total_outward"] == 0


def test_reports_filters_exports_and_csv_injection_guard(world):
    w = world
    out = submitted_approved_outward(w, reference_no="=HYPERLINK(\"http://evil\")")
    gate_out(w, out["id"])
    returned_inward(w, out["id"], 4)
    rep = w.reporter.get("/reports/outstanding_returnables").json()
    assert rep["total"] == 1 and float(rep["items"][0]["qty_pending"]) == 6.0 and float(rep["items"][0]["qty_returned"]) == 4.0
    assert w.reporter.get("/reports/partial_returns").json()["total"] == 1
    assert w.reporter.get("/reports/overdue_returnables").json()["total"] == 0
    assert w.reporter.get("/reports/outward", params={"status": "PARTIALLY_RETURNED"}).json()["total"] == 1
    assert w.reporter.get("/reports/security_activity").json()["total"] == 2
    ap = w.reporter.get("/reports/approvals").json()
    assert ap["total"] == 3 and {i["decision"] for i in ap["items"]} == {"APPROVED"}               # 2 outward levels + 1 inward
    csv_r = w.reporter.get("/reports/outward/export", params={"format": "csv"})
    assert csv_r.status_code == 200 and csv_r.content.startswith(b"\xef\xbb\xbf")
    rows_ = list(csv.reader(io.StringIO(csv_r.content.decode("utf-8-sig"))))
    assert rows_[0][0] == "Gate Pass No." and any(c.startswith("'=HYPERLINK") for c in rows_[1])        # formula injection neutralised
    x = w.reporter.get("/reports/outstanding_returnables/export", params={"format": "xlsx"})
    assert load_workbook(io.BytesIO(x.content)).active["A1"].value == "Outward GP"
    p = w.reporter.get("/reports/outward/export", params={"format": "pdf"})
    assert p.content[:4] == b"%PDF"
    assert w.master.get("/audit-logs", params={"action": "report.export"}).json()["total"] == 3
    assert w.reporter.get("/reports/outward/export", params={"format": "docx"}).status_code == 422


def test_gate_pass_pdf_contains_required_content(world, make_user):
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    returned_inward(w, out["id"], 4)
    r = w.audit.get(f"/gate-passes/{out['id']}/pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and r.content[:4] == b"%PDF"
    from pypdf import PdfReader
    text = " ".join(pg.extract_text() for pg in PdfReader(io.BytesIO(r.content)).pages)
    for needle in ("MTJ-Clothing", out["gate_pass_no"], "Outward Gate Pass", "Laptop", "Returnable", "Prepared By", "Security Checked By", "Admin/Audit Verified",
                   "Approved By", "Actual Gate Out", "Returned", "Pending", "Vehicle", "Seal"):
        assert needle in text, needle
    assert make_user(["approver_l2"]).get(f"/gate-passes/{out['id']}/pdf").status_code == 404 if False else make_user([]).get(f"/gate-passes/{out['id']}/pdf").status_code == 404
    assert w.master.get("/audit-logs", params={"action": "gatepass.pdf.generate"}).json()["total"] == 1


def test_admin_audit_verification_and_security_console(world):
    w = world
    out = submitted_approved_outward(w, vehicle_no="KHI-1")
    q_ = w.sec.get("/security/awaiting-out", params={"q": "khi1"}).json()
    assert q_["total"] == 1 and q_["items"][0]["id"] == out["id"]
    assert w.sec.get("/security/gates").json()[0]["name"] == "Main Security Gate"                   # D-10: one gate
    assert w.audit.post(f"/gate-passes/{out['id']}/verify", {"result": "VERIFIED"}).status_code == 409   # not gated yet
    gate_out(w, out["id"], vehicle_no_verified="KHI-2")                                               # wrong vehicle -> discrepancy
    d = w.audit.get(f"/gate-passes/{out['id']}").json()
    assert d["gate_events"][0]["has_discrepancy"] is True
    assert w.audit.post(f"/gate-passes/{out['id']}/verify", {"result": "DISCREPANCY"}).status_code == 422
    r = w.audit.post(f"/gate-passes/{out['id']}/verify", {"result": "DISCREPANCY", "notes": "Vehicle did not match"})
    assert r.status_code == 200 and r.json()["verifications"][0]["result"] == "DISCREPANCY"
    assert w.sec.post(f"/gate-passes/{out['id']}/verify", {"result": "VERIFIED"}).status_code == 403


def test_notifications_in_app_email_outbox_and_failure_isolation(world):
    w = world
    gp = new_outward(w)
    w.creator.post(f"/gate-passes/{gp['id']}/submit")
    inbox = w.a1.get("/notifications").json()
    assert inbox["unread"] == 1 and inbox["items"][0]["event_type"] == "approval_required"
    assert w.a2.get("/notifications").json()["unread"] == 0
    w.a1.post(f"/gate-passes/{gp['id']}/approve", {})
    assert w.a2.get("/notifications").json()["items"][0]["event_type"] == "approval_required"
    assert w.creator.get("/notifications").json()["items"][0]["event_type"] == "approval_completed"
    nid = w.a1.get("/notifications").json()["items"][0]["id"]
    assert w.a1.post(f"/notifications/{nid}/read").status_code == 200 and w.a1.get("/notifications").json()["unread"] == 0
    assert w.creator2.post(f"/notifications/{nid}/read").status_code == 404
    # e-mail rows are queued; SMTP is not configured here, so delivery fails -> row retried, business transaction unaffected
    with tx() as c:
        assert one(c, "SELECT count(*) AS n FROM notifications WHERE channel = 'EMAIL' AND status = 'PENDING'")["n"] >= 2
    from app.services import notifications
    res = notifications.send_pending_emails()
    assert res["failed"] >= 2 and res["sent"] == 0
    with tx() as c:
        r = one(c, "SELECT attempts, status, last_error, next_attempt_at > now() AS later FROM notifications WHERE channel = 'EMAIL' ORDER BY created_at LIMIT 1")
    assert r["attempts"] == 1 and r["status"] == "PENDING" and "SMTP" in r["last_error"] and r["later"]
    assert w.creator.get(f"/gate-passes/{gp['id']}").json()["status"] == "PENDING_L2"                 # main transaction unaffected
    # user preferences
    assert w.a2.put("/notifications/preferences", [{"event_type": "approval_required", "in_app": False}]).status_code == 200


def test_email_is_sent_through_smtp_when_configured(world, monkeypatch):
    w = world
    sent = []
    from app.services import notifications
    monkeypatch.setattr(notifications, "_send_email", lambda to, subj, body: sent.append((to, subj)))
    gp = new_outward(w)
    w.creator.post(f"/gate-passes/{gp['id']}/submit")
    res = notifications.send_pending_emails()
    assert res["sent"] >= 1 and any("Approval required" in s for _, s in sent)


def test_login_ip_throttle_and_public_settings(client, make_user):
    pub = client.get("/api/v1/settings/public").json()
    assert pub["company.name"] == "MTJ-Clothing" and pub["i18n.timezone"] == "Asia/Karachi" and "security.max_failed_logins" not in pub
    with tx() as c:
        for _ in range(31):
            q(c, "INSERT INTO login_attempts (username_attempted, ip, success) VALUES ('x', '10.0.0.9', false)")
    from app.core import ctx
    tok = ctx.set_(ctx.ReqCtx(ip="10.0.0.9", platform="web"))
    from app.services import auth
    from app.core.errors import AppError
    with pytest.raises(AppError) as e:
        auth.login("anyone", "whatever")
    assert e.value.status == 429
    ctx._ctx.reset(tok)


def test_error_responses_never_leak_internals(client, world):
    w = world
    r = w.creator.get("/gate-passes/not-a-uuid")
    assert r.status_code in (404, 500) and "Traceback" not in r.text and "psycopg" not in r.text and "SELECT" not in r.text
    r = client.get("/api/v1/gate-passes")
    assert r.status_code == 401 and r.json()["code"] == "UNAUTHENTICATED"
    assert client.get("/api/v1/gate-passes", headers={"Authorization": "Bearer garbage"}).json()["code"] == "INVALID_TOKEN"


# ---------------- S3 storage against a real S3-protocol server ----------------
@pytest.fixture(scope="module")
def s3_server():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    proc = subprocess.Popen([sys.executable, "-m", "moto.server", "-p", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); break
        except OSError:
            time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    proc.terminate()


def test_s3_storage_backend_presigned_flow(s3_server, monkeypatch):
    import boto3
    import requests
    from app.core.config import settings
    monkeypatch.setattr(settings, "s3_endpoint", s3_server)
    monkeypatch.setattr(settings, "s3_public_endpoint", s3_server)
    monkeypatch.setattr(settings, "s3_access_key", "test")
    monkeypatch.setattr(settings, "s3_secret_key", "test")
    boto3.client("s3", endpoint_url=s3_server, region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test").create_bucket(Bucket=settings.s3_bucket)
    from app.storage.s3 import S3Storage
    st = S3Storage()
    key = "gatepass/2026/10/abc/x.jpg"
    up = st.presign_put(key, "image/jpeg", 1000)
    assert requests.put(up["url"], data=jpeg_bytes(), headers=up["headers"]).status_code == 200
    assert st.head(key)["size"] == len(jpeg_bytes()) and st.get_range(key, 0, 2) == b"\xff\xd8\xff"
    url = st.presign_get(key, "evidence photo.jpg", "image/jpeg", True)
    got = requests.get(url)
    assert got.status_code == 200 and got.content == jpeg_bytes() and "inline" in got.headers["content-disposition"]
    assert st.head("missing") is None
    st.delete(key)
    assert st.head(key) is None
