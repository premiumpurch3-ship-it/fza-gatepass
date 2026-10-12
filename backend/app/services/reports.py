"""Reports + exports (CSV / XLSX / PDF) and the permission-aware dashboard."""
import csv
import io
from datetime import date

from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..core import settings_store as ss
from ..core.audit import audit
from ..core.config import settings
from ..core.db import rows, scalar, tx
from ..core.errors import Forbidden, Invalid, NotFound
from ..core.paging import Page, envelope
from ..core.timefmt import fmt_d, fmt_dt
from . import gatepass as gp_svc

TZ = settings.timezone
MAX_EXPORT = 50000

CATALOGUE = {
    "outward": ("Outward Gate Pass Report", "reports.view"), "inward": ("Inward Gate Pass Report", "reports.view"),
    "outstanding_returnables": ("Outstanding Returnable Report", "reports.view"), "overdue_returnables": ("Overdue Returnable Report", "reports.view"),
    "partial_returns": ("Partial Return Report", "reports.view"), "security_activity": ("Security Activity Report", "reports.view"),
    "approvals": ("Approval Report", "reports.view"), "audit": ("Audit Report", "audit.view"),
}


def _dates(f, col, p, where):
    if f.get("date_from"):
        where.append(f"({col} AT TIME ZONE :tz)::date >= :df"); p["df"] = f["date_from"]; p["tz"] = TZ
    if f.get("date_to"):
        where.append(f"({col} AT TIME ZONE :tz)::date <= :dt"); p["dt"] = f["date_to"]; p["tz"] = TZ


def _build(code: str, f: dict):
    p, where = {"today": gp_svc.today_local()}, ["TRUE"]
    if code in ("outward", "inward"):
        where.append("t.code = :t"); p["t"] = code.upper()
        _dates(f, "g.created_at", p, where)
        for k, col in (("location_id", "g.location_id"), ("created_by", "g.created_by")):
            if f.get(k):
                where.append(f"{col} = CAST(:{k} AS uuid)"); p[k] = f[k]
        if f.get("status"):
            where.append("g.status = :st"); p["st"] = f["status"].upper()
        if f.get("returnable") is not None:
            where.append("g.has_returnable = :rt"); p["rt"] = f["returnable"]
        where.append("g.status <> 'DRAFT'")
        cols = [("gate_pass_no", "Gate Pass No."), ("created_at", "Created"), ("status", "Status"), ("reference_no", "Reference #"), ("location", "Location"),
                ("vehicle_no", "Vehicle #"), ("seal_no", "Seal #"), ("responsible", "Responsible"), ("created_by_name", "Prepared By"), ("items_count", "Items"),
                ("has_returnable", "Returnable"), ("expected_return_date", "Return Due")]
        sql = f"""SELECT g.gate_pass_no, g.created_at, g.status, g.reference_no, l.name AS location, g.vehicle_no, g.seal_no, coalesce(g.responsible_name, ru.full_name) AS responsible,
                  cu.full_name AS created_by_name, (SELECT count(*) FROM gate_pass_items i WHERE i.gate_pass_id = g.id) AS items_count, g.has_returnable, g.expected_return_date
                  FROM gate_passes g JOIN gate_pass_types t ON t.id = g.type_id LEFT JOIN locations l ON l.id = g.location_id LEFT JOIN users cu ON cu.id = g.created_by
                  LEFT JOIN users ru ON ru.id = g.responsible_user_id WHERE {' AND '.join(where)} ORDER BY g.created_at DESC"""
    elif code in ("outstanding_returnables", "overdue_returnables", "partial_returns"):
        where.append("rr.status IN ('OPEN','PARTIALLY_RETURNED')")
        if code == "overdue_returnables":
            where.append("rr.expected_return_date < :today")
        if code == "partial_returns":
            where.append("ri.qty_returned > 0")
        _dates(f, "g.created_at", p, where)
        if f.get("location_id"):
            where.append("g.location_id = CAST(:loc AS uuid)"); p["loc"] = f["location_id"]
        cols = [("gate_pass_no", "Outward GP"), ("location", "Location"), ("responsible", "Responsible"), ("description", "Item"), ("qty_out", "Original Qty"),
                ("qty_returned", "Returned"), ("qty_adjusted", "Written off"), ("qty_pending", "Pending"), ("unit", "Unit"), ("expected_return_date", "Return Due"),
                ("days_overdue", "Days Overdue"), ("return_status", "Status")]
        sql = f"""SELECT g.gate_pass_no, l.name AS location, coalesce(g.responsible_name, ru.full_name) AS responsible, i.description, ri.qty_out, ri.qty_returned, ri.qty_adjusted,
                  ri.qty_pending, u.code AS unit, rr.expected_return_date, GREATEST(0, :today - rr.expected_return_date) AS days_overdue, rr.status AS return_status
                  FROM returnable_items ri JOIN returnable_records rr ON rr.id = ri.record_id JOIN gate_passes g ON g.id = rr.source_gate_pass_id
                  JOIN gate_pass_items i ON i.id = ri.source_item_id JOIN units_of_measure u ON u.id = ri.unit_id LEFT JOIN locations l ON l.id = g.location_id
                  LEFT JOIN users ru ON ru.id = g.responsible_user_id WHERE {' AND '.join(where)} AND ri.qty_pending > 0 ORDER BY rr.expected_return_date, g.gate_pass_no, i.line_no"""
    elif code == "security_activity":
        _dates(f, "e.occurred_at", p, where)
        if f.get("created_by"):
            where.append("e.recorded_by = CAST(:rb AS uuid)"); p["rb"] = f["created_by"]
        cols = [("occurred_at", "Time"), ("event_type", "Event"), ("gate_pass_no", "Gate Pass"), ("type", "Type"), ("gate", "Gate"), ("recorded_by", "Security User"),
                ("vehicle_no_verified", "Vehicle Verified"), ("seal_no_verified", "Seal Verified"), ("has_discrepancy", "Discrepancy"), ("remarks", "Remarks")]
        sql = f"""SELECT e.occurred_at, e.event_type, g.gate_pass_no, t.code AS type, ga.name AS gate, u.full_name AS recorded_by, e.vehicle_no_verified, e.seal_no_verified,
                  e.has_discrepancy, e.remarks FROM gate_pass_gate_events e JOIN gate_passes g ON g.id = e.gate_pass_id JOIN gate_pass_types t ON t.id = g.type_id
                  JOIN gates ga ON ga.id = e.gate_id JOIN users u ON u.id = e.recorded_by WHERE {' AND '.join(where)} ORDER BY e.occurred_at DESC"""
    elif code == "approvals":
        _dates(f, "a.decided_at", p, where)
        if f.get("created_by"):
            where.append("a.approver_id = CAST(:ap AS uuid)"); p["ap"] = f["created_by"]
        if f.get("status"):
            where.append("a.decision = :dec"); p["dec"] = f["status"].upper()
        cols = [("decided_at", "Decided"), ("gate_pass_no", "Gate Pass"), ("type", "Type"), ("round_no", "Round"), ("level", "Level"), ("approver_name", "Approver"),
                ("decision", "Decision"), ("comments", "Comments"), ("turnaround_hours", "Hours since submit")]
        sql = f"""SELECT a.decided_at, g.gate_pass_no, t.code AS type, a.round_no, a.level, a.approver_name, a.decision, a.comments,
                  round(extract(epoch FROM (a.decided_at - g.submitted_at)) / 3600.0, 1) AS turnaround_hours
                  FROM gate_pass_approvals a JOIN gate_passes g ON g.id = a.gate_pass_id JOIN gate_pass_types t ON t.id = g.type_id WHERE {' AND '.join(where)} ORDER BY a.decided_at DESC"""
    elif code == "audit":
        _dates(f, "a.occurred_at", p, where)
        if f.get("created_by"):
            where.append("a.actor_user_id = CAST(:au AS uuid)"); p["au"] = f["created_by"]
        cols = [("occurred_at", "Time"), ("actor_username", "User"), ("action", "Action"), ("entity_type", "Entity"), ("entity_id", "Entity ID"), ("summary", "Summary"), ("severity", "Severity")]
        sql = f"SELECT a.occurred_at, a.actor_username, a.action, a.entity_type, a.entity_id, a.summary, a.severity FROM audit_logs a WHERE {' AND '.join(where)} ORDER BY a.id DESC"
    else:
        raise NotFound("Report")
    return cols, sql, p


def catalogue(user):
    return [{"code": k, "title": v[0]} for k, v in CATALOGUE.items() if v[1] in user["perms"]]


def _guard(user, code):
    if code not in CATALOGUE:
        raise NotFound("Report")
    if CATALOGUE[code][1] not in user["perms"]:
        raise Forbidden()


def run(user, code, f, pg: Page):
    _guard(user, code)
    cols, sql, p = _build(code, f)
    with tx() as c:
        total = scalar(c, f"SELECT count(*) FROM ({sql}) x", **p)
        data = rows(c, f"{sql} LIMIT :lim OFFSET :off", lim=pg.size, off=pg.offset, **p)
        audit(c, "report.run", "report", code, f"Report '{CATALOGUE[code][0]}' viewed", after={"filters": {k: v for k, v in f.items() if v}})
    return {"title": CATALOGUE[code][0], "columns": [{"key": k, "label": l} for k, l in cols], **envelope(data, total, pg)}


def _cell(v):
    if v is None:
        return ""
    if hasattr(v, "tzinfo") and getattr(v, "hour", None) is not None:
        return fmt_dt(v)
    if isinstance(v, date):
        return fmt_d(v)
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
        return "'" + v        # spreadsheet formula-injection guard
    return v


def export(user, code, f, fmt: str):
    _guard(user, code)
    if "reports.export" not in user["perms"]:
        raise Forbidden()
    cols, sql, p = _build(code, f)
    with tx() as c:
        data = rows(c, f"{sql} LIMIT {MAX_EXPORT}", **p)
        audit(c, "report.export", "report", code, f"Report '{CATALOGUE[code][0]}' exported as {fmt}", after={"filters": {k: v for k, v in f.items() if v}, "rows": len(data)})
    title = CATALOGUE[code][0]
    table = [[l for _, l in cols]] + [[_cell(r[k]) for k, _ in cols] for r in data]
    name = f"{code}_{date.today().isoformat()}"
    if fmt == "csv":
        out = io.StringIO()
        csv.writer(out).writerows(table)
        return ("\ufeff" + out.getvalue()).encode("utf-8"), "text/csv; charset=utf-8", f"{name}.csv"
    if fmt == "xlsx":
        wb = Workbook(); ws = wb.active; ws.title = title[:31]
        for r in table:
            ws.append([str(x) if not isinstance(x, (int, float)) else x for x in r])
        for cell in ws[1]:
            cell.font = cell.font.copy(bold=True)
        b = io.BytesIO(); wb.save(b)
        return b.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", f"{name}.xlsx"
    if fmt == "pdf":
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=10 * mm, rightMargin=10 * mm, topMargin=10 * mm, bottomMargin=10 * mm, title=title)
        st = getSampleStyleSheet()
        small = ParagraphStyle("sm", parent=st["Normal"], fontSize=7, leading=8.5)
        el = [Paragraph(f"{ss.get('company.name') or 'MTJ-Clothing'} — {title}", st["Title"]), Paragraph(f"Generated {fmt_dt(__import__('datetime').datetime.now(__import__('datetime').timezone.utc))} — {len(data)} rows", small), Spacer(1, 4)]
        t = Table([[Paragraph(str(x), small) for x in r] for r in table], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        doc.build(el + [t])
        return buf.getvalue(), "application/pdf", f"{name}.pdf"
    raise Invalid("Unsupported format", "VALIDATION_ERROR")


# ---------------- dashboard ----------------
def dashboard(user, f: dict):
    p = user["perms"]
    vis, vp = gp_svc.visibility_sql(user)
    params, where = dict(vp), [vis, "g.status <> 'DRAFT'"]
    _dates(f, "g.created_at", params, where)
    if f.get("location_id"):
        where.append("g.location_id = CAST(:loc AS uuid)"); params["loc"] = f["location_id"]
    if f.get("status"):
        where.append("g.status = :st"); params["st"] = f["status"].upper()
    if f.get("type"):
        where.append("t.code = :ty"); params["ty"] = f["type"].upper()
    if f.get("returnable") is not None:
        where.append("g.has_returnable = :rt"); params["rt"] = f["returnable"]
    if f.get("responsible_user_id"):
        where.append("g.responsible_user_id = CAST(:ru AS uuid)"); params["ru"] = f["responsible_user_id"]
    W = " AND ".join(where)
    base = f"FROM gate_passes g JOIN gate_pass_types t ON t.id = g.type_id LEFT JOIN returnable_records rr ON rr.source_gate_pass_id = g.id WHERE {W}"
    today = gp_svc.today_local()
    out = {}
    with tx() as c:
        n = lambda extra, **kw: scalar(c, f"SELECT count(*) {base} AND {extra}", **params, **kw)
        out["total_outward"] = n("t.code = 'OUTWARD'")
        out["total_inward"] = n("t.code = 'INWARD'")
        if any(x in p for x in ("approval.level1", "approval.level2", "inward.approve")):
            conds = []
            if "approval.level1" in p: conds.append("(t.code = 'OUTWARD' AND g.status = 'PENDING_L1')")
            if "approval.level2" in p: conds.append("(t.code = 'OUTWARD' AND g.status = 'PENDING_L2')")
            if "inward.approve" in p: conds.append("(t.code = 'INWARD' AND g.status = 'PENDING_L1')")
            out["pending_approvals"] = n("(" + " OR ".join(conds) + ") AND g.created_by <> CAST(:me AS uuid)", me=str(user["id"]))
        if "security.gateout" in p:
            out["pending_gate_out"] = n("t.code = 'OUTWARD' AND g.status = 'APPROVED'")
        if "security.gatein" in p:
            out["pending_gate_in"] = n("t.code = 'INWARD' AND g.status = 'APPROVED'")
        if "return.view" in p:
            out["outstanding_returnables"] = n("rr.status IN ('OPEN','PARTIALLY_RETURNED')")
            out["overdue_returnables"] = n("rr.status IN ('OPEN','PARTIALLY_RETURNED') AND rr.expected_return_date < :today", today=today)
            out["partially_returned"] = n("rr.status = 'PARTIALLY_RETURNED'")
            out["fully_returned"] = n("rr.status = 'COMPLETED'")
            out["closed_writeoff"] = n("rr.status = 'CLOSED_ADJUSTED'")
        out["recent"] = rows(c, f"""SELECT g.id, g.gate_pass_no, t.code AS type, g.status, g.created_at, l.name AS location FROM gate_passes g JOIN gate_pass_types t ON t.id = g.type_id
                                    LEFT JOIN locations l ON l.id = g.location_id LEFT JOIN returnable_records rr ON rr.source_gate_pass_id = g.id WHERE {W} ORDER BY g.created_at DESC LIMIT 10""", **params)
        if "gatepass.create" in p:
            out["my_drafts"] = scalar(c, "SELECT count(*) FROM gate_passes WHERE created_by = :u AND status = 'DRAFT'", u=user["id"])
            out["my_rejected"] = scalar(c, "SELECT count(*) FROM gate_passes WHERE created_by = :u AND status = 'REJECTED'", u=user["id"])
        if "admin.users" in p:   # admin-only
            out["active_users"] = scalar(c, "SELECT count(*) FROM users WHERE is_active")
        if "audit.view" in p:
            out["security_events_24h"] = scalar(c, "SELECT count(*) FROM audit_logs WHERE severity = 'SECURITY' AND occurred_at > now() - interval '24 hours'")
    return out
