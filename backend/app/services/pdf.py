"""Printable Gate Pass PDF (rendered from the pinned form snapshot + live approval/security/return data)."""
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..core import settings_store as ss
from ..core.audit import audit
from ..core.db import tx
from ..core.errors import Forbidden
from ..core.timefmt import fmt_d, fmt_dt
from . import gatepass as gp_svc

NAVY = colors.HexColor("#14325c")
GREY = colors.HexColor("#eef1f5")


def _p(text, style):
    return Paragraph(str(text if text is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), style)


def gate_pass_pdf(user, gp_id) -> tuple[bytes, str]:
    d = gp_svc.get_detail(user, gp_id)
    if d["status"] == "DRAFT" and d["created_by"] != user["id"]:
        raise Forbidden()
    ss_ = getSampleStyleSheet()
    s = ParagraphStyle("s", parent=ss_["Normal"], fontSize=8.5, leading=11)
    sb = ParagraphStyle("sb", parent=s, fontName="Helvetica-Bold")
    h1 = ParagraphStyle("h1", parent=ss_["Title"], fontSize=18, textColor=NAVY, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss_["Heading3"], fontSize=10.5, textColor=NAVY, spaceBefore=8, spaceAfter=3)
    with tx() as c:
        company = ss.get("company.name", c) or "MTJ-Clothing"
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=12 * mm, bottomMargin=14 * mm,
                            title=f"Gate Pass {d['gate_pass_no'] or 'Draft'}", author=company)
    el = [Paragraph(company, h1), Paragraph(f"{d['type'].title()} Gate Pass" + ("  —  DRAFT" if d["status"] == "DRAFT" else ""), ParagraphStyle("t", parent=s, fontSize=12, textColor=NAVY))]
    el.append(Spacer(1, 4))
    v = d["values"]
    head = [["Gate Pass No.", d["gate_pass_no"] or "(draft)", "Status", d["status"].replace("_", " ").title()],
            ["Date", fmt_dt(d["submitted_at"] or d["created_at"]), "Type", d["type"].title()],
            ["To Location" if d["direction"] == "OUT" else "From Location", (d["location"] or {}).get("name", ""), "Reference #", d["reference_no"] or ""],
            ["Vehicle #", d["vehicle_no"] or "", "Seal #", d["seal_no"] or ""],
            ["Time Out (planned)" if d["direction"] == "OUT" else "Time In (planned)", fmt_dt(d["planned_datetime"]), "Responsible", d["responsible_display"] or ""],
            ["Department", (d["department"] or {}).get("name", ""), "Purpose", (d["purpose_value"] or "").replace("_", " ").title()]]
    if d["has_returnable"]:
        head.append(["Return Due Date", fmt_d(d["expected_return_date"]), "Received By", d["received_by_name"] or ""])
    else:
        head.append(["Received By", d["received_by_name"] or "", "", ""])
    for e in d["gate_events"]:
        head.append([("Actual Gate Out" if e["event_type"] == "GATE_OUT" else "Actual Gate In"), fmt_dt(e["occurred_at"]), "Gate / Security", f"{e['gate_name']} / {e['recorded_by_name']}"])
    # configurable (custom) fields flagged for PDF
    for sec in d["form_snapshot"]["sections"]:
        for f in sec["fields"]:
            if f["storage"] == "CUSTOM" and f["scope"] == "HEADER" and f["flags"]["pdf"] and v.get(f["key"]) not in (None, ""):
                val = v[f["key"]]
                head.append([f["label"], ", ".join(val) if isinstance(val, list) else ("Yes" if val is True else "No" if val is False else val), "", ""])
    t = Table([[_p(a, sb), _p(b, s), _p(c_, sb), _p(d_, s)] for a, b, c_, d_ in head], colWidths=[34 * mm, 56 * mm, 32 * mm, 56 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (0, -1), GREY), ("BACKGROUND", (2, 0), (2, -1), GREY), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    el += [t, Paragraph("Items", h2)]
    ret = d["direction"] == "OUT" and d["return_record"]
    cols = ["S/No", "Description", "Qty", "Unit", "Cartons", "Pieces", "Returnable"] + (["Verified"] if d["gate_events"] else []) + (["Returned", "Pending"] if ret else [])
    shb = ParagraphStyle("shb", parent=sb, fontSize=7.2, leading=9)
    rows_ = [[_p(x, shb) for x in cols]]
    for i in d["items"]:
        r = [i["line_no"], i["description"] + (f" ({i['item_code']})" if i["item_code"] else ""), f"{i['quantity']:g}", i["unit_code"], i["cartons"] if i["cartons"] is not None else "",
             i["pieces"] if i["pieces"] is not None else "", "Yes" if i["is_returnable"] else "No"]
        if d["gate_events"]:
            r.append(f"{i['verified_quantity']:g}" if i["verified_quantity"] is not None else "")
        if ret:
            rt = i.get("returnable")
            r += [f"{rt['qty_returned']:g}" if rt else "", f"{rt['qty_pending']:g}" if rt else ""]
        rows_.append([_p(x, s) for x in r])
    wid = [10, 44, 15, 12, 16, 15, 20] + ([17] if d["gate_events"] else []) + ([17, 17] if ret else [])
    k = 182 / sum(wid)
    it = Table(rows_, colWidths=[w * k * mm for w in wid], repeatRows=1)
    it.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), GREY), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    el.append(it)
    if d["links"].get("returns_against"):
        el += [Spacer(1, 4), _p("Returns against: " + ", ".join(x["gate_pass_no"] for x in d["links"]["returns_against"]), s)]
    if d["links"].get("returned_by"):
        el += [Spacer(1, 4), _p("Returned via: " + ", ".join(x["gate_pass_no"] for x in d["links"]["returned_by"]), s)]
    if d["return_record"]:
        rr = d["return_record"]
        el += [Spacer(1, 3), _p(f"Return status: {rr['status'].replace('_', ' ').title()}  |  Due: {fmt_d(rr['expected_return_date'])}" + (f"  |  Closed: {rr['close_reason']}" if rr.get("close_reason") else ""), s)]
    if d["remarks"]:
        el += [Paragraph("Remarks", h2), _p(d["remarks"], s)]
    el.append(Paragraph("Approvals & Verification", h2))
    appr = {(a["round_no"], a["level"]): a for a in d["approvals"]}
    approved = [a for a in d["approvals"] if a["decision"] == "APPROVED" and a["round_no"] == d["round_no"]]
    sign = [[_p("Prepared By", sb), _p("Approved By", sb), _p("Received By", sb), _p("Security Checked By", sb), _p("Admin/Audit Verified", sb)]]
    ver = d["verifications"][0] if d["verifications"] else None
    gev = d["gate_events"][-1] if d["gate_events"] else None
    sign.append([_p(f"{d['created_by_name']}\n{fmt_dt(d['submitted_at'])}".replace("\n", "<br/>"), s) if False else Paragraph(f"{d['created_by_name']}<br/>{fmt_dt(d['submitted_at'])}", s),
                 Paragraph("<br/>".join(f"L{a['level']}: {a['approver_name']}<br/>{fmt_dt(a['decided_at'])}" for a in approved) or "—", s),
                 Paragraph(d["received_by_name"] or "—", s),
                 Paragraph(f"{gev['recorded_by_name']}<br/>{fmt_dt(gev['occurred_at'])}" if gev else "—", s),
                 Paragraph(f"{ver['verified_by_name']}<br/>{fmt_dt(ver['verified_at'])}<br/>{ver['result'].title()}" if ver else "—", s)])
    st = Table(sign, colWidths=[36 * mm] * 5)
    st.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), GREY), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("MINROWHEIGHT", (0, 1), (-1, 1), 18 * mm)]))
    el += [st, Spacer(1, 4), _p("Digital approval history is the primary approval evidence; no physical signature is required.", ParagraphStyle("n", parent=s, fontSize=7, textColor=colors.grey))]

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.grey)
        canvas.drawString(14 * mm, 8 * mm, f"{company} — {d['gate_pass_no'] or 'Draft'} — generated {fmt_dt(__import__('datetime').datetime.now(__import__('datetime').timezone.utc))}")
        canvas.drawRightString(196 * mm, 8 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(el, onFirstPage=footer, onLaterPages=footer)
    with tx() as c:
        audit(c, "gatepass.pdf.generate", "gate_pass", d["id"], f"PDF generated for {d['gate_pass_no'] or 'draft'}", gate_pass_id=d["id"])
    return buf.getvalue(), f"{d['gate_pass_no'] or 'draft'}.pdf"
