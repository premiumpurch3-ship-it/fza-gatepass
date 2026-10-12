"""Gate Pass aggregate: create/update/submit/recall/cancel, numbering, visibility, search, detail."""
import hashlib
import json
import re
from datetime import date, datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from ..core import ctx, settings_store as ss
from ..core.audit import audit, diff
from ..core.config import settings
from ..core.db import J, jsonable, one, q, rows, scalar, tx
from ..core.errors import AppError, Conflict, Forbidden, Invalid, NotFound
from ..core.paging import Page, envelope
from . import formrt, notifications as nt

TZ = ZoneInfo(settings.timezone)
EDITABLE = ("DRAFT", "REJECTED")
CANCELLABLE = ("DRAFT", "REJECTED", "PENDING_L1", "PENDING_L2", "APPROVED")
POST_GATE_OUT = ("GATE_OUT", "PENDING_RETURN", "PARTIALLY_RETURNED", "COMPLETED", "CLOSED")


def today_local() -> date:
    return datetime.now(TZ).date()


# ---------------- helpers ----------------
def load(c, gp_id, lock=False):
    gp = one(c, f"""SELECT g.*, t.code AS type_code, t.direction, t.approval_levels AS type_levels, t.min_photos, t.max_photos
                    FROM gate_passes g JOIN gate_pass_types t ON t.id = g.type_id WHERE g.id = CAST(:i AS uuid) {'FOR UPDATE OF g' if lock else ''}""", i=str(gp_id))
    if not gp:
        raise NotFound("Gate pass")
    return gp


def set_status(c, gp, to: str, reason: str | None = None, actor_id=None, **cols):
    """The single place that changes status: updates the row and writes the history row in one go."""
    sets = ["status = :to", "status_changed_at = now()", "row_version = row_version + 1"] + [f"{k} = :{k}" for k in cols]
    q(c, f"UPDATE gate_passes SET {', '.join(sets)} WHERE id = :id", to=to, id=gp["id"], **cols)
    q(c, """INSERT INTO gate_pass_status_history (gate_pass_id, from_status, to_status, actor_id, reason, revision_no, round_no)
            VALUES (:g, :f, :t, :a, :r, :rev, :rnd)""", g=gp["id"], f=gp["status"], t=to, a=actor_id or ctx.get().user_id, r=reason,
      rev=gp["revision_no"], rnd=gp["round_no"])
    gp["status"] = to
    for k, v in cols.items():
        gp[k] = v


def format_number(c, now: datetime) -> str:
    year = now.astimezone(TZ).year
    n = scalar(c, """INSERT INTO number_sequences (scope_key, last_value) VALUES (:k, 1)
                     ON CONFLICT (scope_key) DO UPDATE SET last_value = number_sequences.last_value + 1, updated_at = now() RETURNING last_value""", k=f"GP:{year}")
    fmt = ss.get("numbering.format", c) or "GP-{YYYY}-{SEQ:6}"
    out = fmt.replace("{YYYY}", str(year))
    return re.sub(r"\{SEQ:(\d+)\}", lambda m: str(n).zfill(int(m.group(1))), out)


def visibility_sql(user, a="g", t="t"):
    p = user["perms"]
    if "gatepass.view" in p:
        return "TRUE", {}
    parts = [f"{a}.created_by = :v_uid", f"({a}.responsible_user_id = :v_uid AND {a}.status <> 'DRAFT')",
             f"EXISTS (SELECT 1 FROM gate_pass_approvals ap WHERE ap.gate_pass_id = {a}.id AND ap.approver_id = :v_uid)"]
    if "approval.level1" in p or "approval.level2" in p:
        parts.append(f"({t}.code = 'OUTWARD' AND {a}.status <> 'DRAFT')")
    if "inward.approve" in p:
        parts.append(f"({t}.code = 'INWARD' AND {a}.status <> 'DRAFT')")
    if "security.gateout" in p:
        parts.append(f"({t}.code = 'OUTWARD' AND {a}.status IN ('APPROVED','GATE_OUT','PENDING_RETURN','PARTIALLY_RETURNED','COMPLETED','CLOSED'))")
    if "security.gatein" in p:
        parts.append(f"({t}.code = 'INWARD' AND {a}.status IN ('APPROVED','GATE_IN','COMPLETED','CLOSED'))")
        parts.append(f"({a}.has_returnable AND {a}.status IN ('GATE_OUT','PENDING_RETURN','PARTIALLY_RETURNED','COMPLETED','CLOSED'))")
    if "return.view" in p:
        parts.append(f"({a}.has_returnable AND {a}.status IN ('GATE_OUT','PENDING_RETURN','PARTIALLY_RETURNED','COMPLETED','CLOSED'))")
        parts.append(f"EXISTS (SELECT 1 FROM returnable_transactions rt WHERE rt.inward_gate_pass_id = {a}.id)")
    if "admin.verify" in p:
        parts.append(f"{a}.status <> 'DRAFT'")
    return "(" + " OR ".join(parts) + ")", {"v_uid": str(user["id"])}


def check_visible(c, user, gp_id):
    w, p = visibility_sql(user)
    if not one(c, f"SELECT 1 AS x FROM gate_passes g JOIN gate_pass_types t ON t.id = g.type_id WHERE g.id = CAST(:i AS uuid) AND {w}", i=str(gp_id), **p):
        raise NotFound("Gate pass")   # 404, never 403: do not reveal existence


def _snapshot(c, gp):
    return one(c, "SELECT snapshot, version_no FROM form_versions WHERE id = :v", v=gp["form_version_id"])


# ---------------- create / update ----------------
def _prepare(c, snap, values: dict, items: list[dict], strict: bool, require_item_basics=True):
    clean, errs = formrt.validate_scope(c, snap, "HEADER", values or {}, strict)
    core, custom = formrt.split_header(snap, clean)
    irows = []
    for i, it in enumerate(items or []):
        ic, ie = formrt.validate_scope(c, snap, "ITEM", it.get("values") or {}, strict or require_item_basics)
        for e in ie:
            e["item_index"] = i
        errs += ie
        icore, icustom = formrt.split_item(snap, ic)
        irows.append({"id": it.get("id"), "core": icore, "custom": icustom, "source": it.get("source_outward_item_id")})
    if errs:
        raise Invalid("Please correct the highlighted fields", "VALIDATION_ERROR", errors=errs)
    return core, custom, irows


HEADER_COLS = ["reference_no", "vehicle_no", "seal_no", "planned_datetime", "location_id", "department_id", "responsible_user_id", "responsible_name",
               "purpose_value", "category_value", "received_by_name", "inward_kind", "expected_return_date", "remarks"]


def _write_items(c, gp_id, irows):
    existing = {str(r["id"]) for r in rows(c, "SELECT id FROM gate_pass_items WHERE gate_pass_id = :g", g=gp_id)}
    keep = {str(r["id"]) for r in irows if r["id"]}
    if keep - existing:
        raise Invalid("Unknown item id", "VALIDATION_ERROR")
    for rid in existing - keep:
        q(c, "UPDATE gate_pass_attachments SET gate_pass_item_id = NULL WHERE gate_pass_item_id = :i", i=rid)
        q(c, "UPDATE gate_pass_items SET source_outward_item_id = NULL WHERE source_outward_item_id = :i", i=rid)
        q(c, "DELETE FROM gate_pass_items WHERE id = :i", i=rid)
    # temporarily shift line numbers to avoid unique collisions, then renumber 1..n
    q(c, "UPDATE gate_pass_items SET line_no = line_no + 100000 WHERE gate_pass_id = :g", g=gp_id)
    has_ret = False
    for n, r in enumerate(irows, 1):
        core = r["core"]
        cols = {"description": core.get("description"), "item_code": core.get("item_code"), "quantity": core.get("quantity"), "unit_id": core.get("unit_id"),
                "cartons": core.get("cartons"), "pieces": core.get("pieces"), "is_returnable": bool(core.get("is_returnable", False)),
                "condition_value": core.get("condition_value"), "remarks": core.get("remarks")}
        if cols["description"] is None or cols["quantity"] is None or cols["unit_id"] is None:
            raise Invalid("Each item needs a description, quantity and unit", "VALIDATION_ERROR", errors=[{"item_index": n - 1, "message": "Description, quantity and unit are required"}])
        has_ret = has_ret or cols["is_returnable"]
        if r["id"]:
            q(c, """UPDATE gate_pass_items SET line_no = :n, item_code = :item_code, description = :description, quantity = :quantity, unit_id = CAST(:unit_id AS uuid),
                    cartons = :cartons, pieces = :pieces, is_returnable = :is_returnable, condition_value = :condition_value, remarks = :remarks,
                    custom_data = CAST(:cd AS jsonb), source_outward_item_id = CAST(:src AS uuid) WHERE id = CAST(:id AS uuid)""",
              n=n, cd=J(r["custom"]), src=r["source"], id=r["id"], **cols)
        else:
            q(c, """INSERT INTO gate_pass_items (gate_pass_id, line_no, item_code, description, quantity, unit_id, cartons, pieces, is_returnable, condition_value,
                    remarks, custom_data, source_outward_item_id) VALUES (:g, :n, :item_code, :description, :quantity, CAST(:unit_id AS uuid), :cartons, :pieces,
                    :is_returnable, :condition_value, :remarks, CAST(:cd AS jsonb), CAST(:src AS uuid))""", g=gp_id, n=n, cd=J(r["custom"]), src=r["source"], **cols)
    q(c, "UPDATE gate_passes SET has_returnable = :h WHERE id = :g", h=has_ret, g=gp_id)


def create(user, type_code: str, values: dict, items: list[dict], client_request_id: str | None):
    with tx() as c:
        t = one(c, "SELECT t.id, t.code, d.current_version_id FROM gate_pass_types t JOIN form_definitions d ON d.gate_pass_type_id = t.id WHERE t.code = :c AND t.is_active", c=type_code.upper())
        if not t:
            raise NotFound("Gate pass type")
        if client_request_id:
            ex = one(c, "SELECT id FROM gate_passes WHERE created_by = :u AND client_request_id = CAST(:r AS uuid)", u=user["id"], r=client_request_id)
            if ex:
                return get_detail(user, ex["id"])
        snap = one(c, "SELECT snapshot FROM form_versions WHERE id = :v", v=t["current_version_id"])["snapshot"]
        core, custom, irows = _prepare(c, snap, values, items, strict=False)
        gp = one(c, """INSERT INTO gate_passes (type_id, form_version_id, created_by, client_request_id, custom_data) VALUES (:t, :v, :u, CAST(:r AS uuid), CAST(:cd AS jsonb))
                       RETURNING id""", t=t["id"], v=t["current_version_id"], u=user["id"], r=client_request_id, cd=J(custom))
        _apply_core(c, gp["id"], core)
        q(c, "INSERT INTO gate_pass_status_history (gate_pass_id, from_status, to_status, actor_id, revision_no, round_no) VALUES (:g, NULL, 'DRAFT', :u, 0, 0)", g=gp["id"], u=user["id"])
        _write_items(c, gp["id"], irows)
        audit(c, "gatepass.create", "gate_pass", gp["id"], f"{t['code'].title()} gate pass draft created", gate_pass_id=gp["id"], after={"type": t["code"]})
        gid = gp["id"]
    return get_detail(user, gid)


def _apply_core(c, gp_id, core: dict):
    cols = {k: v for k, v in core.items() if k in HEADER_COLS}
    if cols:
        casts = {"location_id": "CAST(:location_id AS uuid)", "department_id": "CAST(:department_id AS uuid)", "responsible_user_id": "CAST(:responsible_user_id AS uuid)"}
        q(c, f"UPDATE gate_passes SET {', '.join(f'{k} = {casts.get(k, f':{k}')}' for k in cols)} WHERE id = :id", id=gp_id, **cols)


def update(user, gp_id, row_version: int, values: dict, items: list[dict] | None):
    with tx() as c:
        gp = load(c, gp_id, lock=True)
        if gp["created_by"] != user["id"] and "gatepass.edit" not in user["perms"]:
            raise NotFound("Gate pass")
        if gp["created_by"] != user["id"]:
            raise NotFound("Gate pass")
        if "gatepass.edit" not in user["perms"]:
            raise Forbidden()
        if gp["status"] not in EDITABLE:
            raise Conflict("NOT_EDITABLE", "This gate pass can no longer be edited. Cancel it and create a new one if a correction is needed.")
        if gp["row_version"] != row_version:
            raise Conflict("STALE_VERSION", "This gate pass was changed elsewhere. Reload and try again.", current_row_version=gp["row_version"])
        snap = _snapshot(c, gp)["snapshot"]
        existing_items = items is None
        core, custom, irows = _prepare(c, snap, values, items or [], strict=False)
        before = {k: gp.get(k) for k in HEADER_COLS}
        # merge: only provided keys change
        merged_custom = {**(gp["custom_data"] or {}), **custom}
        q(c, "UPDATE gate_passes SET custom_data = CAST(:cd AS jsonb), row_version = row_version + 1 WHERE id = :id", cd=J(merged_custom), id=gp["id"])
        _apply_core(c, gp["id"], core)
        if items is not None:
            _write_items(c, gp["id"], irows)
        after_row = one(c, "SELECT * FROM gate_passes WHERE id = :i", i=gp["id"])
        b, a = diff(before, {k: after_row.get(k) for k in HEADER_COLS})
        audit(c, "gatepass.update", "gate_pass", gp["id"], f"Gate pass {gp['gate_pass_no'] or 'draft'} edited", before=b, after={**a, **({"items_replaced": len(items)} if items is not None else {})}, gate_pass_id=gp["id"])
    return get_detail(user, gp_id)


def move_to_latest_form(user, gp_id):
    """D-17: controlled, explicit migration of a draft/rejected pass to the newest form version; unknown fields are reported, not silently dropped."""
    with tx() as c:
        gp = load(c, gp_id, lock=True)
        if gp["created_by"] != user["id"] or "gatepass.edit" not in user["perms"]:
            raise NotFound("Gate pass")
        if gp["status"] not in EDITABLE:
            raise Conflict("NOT_EDITABLE", "Only drafts or rejected passes can move to the latest form")
        cur = scalar(c, "SELECT d.current_version_id FROM form_definitions d WHERE d.gate_pass_type_id = :t", t=gp["type_id"])
        if str(cur) == str(gp["form_version_id"]):
            raise Conflict("ALREADY_LATEST", "This gate pass already uses the latest form")
        new = one(c, "SELECT snapshot FROM form_versions WHERE id = :v", v=cur)["snapshot"]
        old = _snapshot(c, gp)["snapshot"]
        newkeys = {f["key"] for f in formrt.fields_of(new, "HEADER")}
        dropped = [k for k, v in (gp["custom_data"] or {}).items() if k not in newkeys and v not in (None, "")]
        kept = {k: v for k, v in (gp["custom_data"] or {}).items() if k in newkeys}
        q(c, "UPDATE gate_passes SET form_version_id = :v, custom_data = CAST(:cd AS jsonb), row_version = row_version + 1 WHERE id = :g", v=cur, cd=J(kept), g=gp["id"])
        audit(c, "gatepass.form.move_to_latest", "gate_pass", gp["id"], "Draft moved to the latest form version", gate_pass_id=gp["id"],
              before={"form_version_id": gp["form_version_id"]}, after={"form_version_id": cur, "dropped_custom_fields": dropped})
    d = get_detail(user, gp_id)
    d["moved_to_latest"] = {"dropped_custom_fields": dropped}
    return d


# ---------------- submit ----------------
def _pending_for_source(c, source_ids: list[str]):
    return {str(r["source_item_id"]): r for r in rows(c, "SELECT source_item_id, qty_pending, unit_id FROM returnable_items WHERE source_item_id = ANY(CAST(:s AS uuid[]))", s=source_ids)}


def _validate_for_submit(c, gp, snap):
    values = formrt.header_values(snap, gp)
    items = rows(c, "SELECT * FROM gate_pass_items WHERE gate_pass_id = :g ORDER BY line_no", g=gp["id"])
    errs = []
    _, e = formrt.validate_scope(c, snap, "HEADER", values, strict=True)
    errs += e
    for i, it in enumerate(items):
        _, ie = formrt.validate_scope(c, snap, "ITEM", formrt.item_values(snap, it), strict=True)
        errs += [{**x, "item_index": i} for x in ie]
    if not items:
        errs.append({"field": "items", "label": "Items", "message": "Add at least one item"})
    ret = any(i["is_returnable"] for i in items)
    if ret and not gp["expected_return_date"]:
        errs.append({"field": "expected_return_date", "label": "Return Due Date", "message": "Return due date is required when any item is returnable"})
    if ret and gp["expected_return_date"] and gp["expected_return_date"] < today_local():
        errs.append({"field": "expected_return_date", "label": "Return Due Date", "message": "Return due date cannot be in the past"})
    if gp["direction"] == "OUT" and ret is False and gp["expected_return_date"]:
        pass
    atts = rows(c, "SELECT kind, status FROM gate_pass_attachments WHERE gate_pass_id = :g AND status <> 'DELETED'", g=gp["id"])
    if any(a["status"] in ("PENDING_UPLOAD", "UPLOADED") for a in atts):
        errs.append({"field": "attachments", "label": "Attachments", "message": "Some uploads are not finished yet"})
    if any(a["status"] == "QUARANTINED" for a in atts):
        errs.append({"field": "attachments", "label": "Attachments", "message": "A rejected file is attached. Remove it first"})
    photos = sum(1 for a in atts if a["kind"] in ("PHOTO_CAPTURE", "PHOTO_UPLOAD") and a["status"] == "READY")
    if photos < gp["min_photos"]:
        errs.append({"field": "photos", "label": "Photos", "message": f"At least {gp['min_photos']} product/material photo is required before submission"})
    if photos > gp["max_photos"]:
        errs.append({"field": "photos", "label": "Photos", "message": f"At most {gp['max_photos']} photos are allowed"})
    if gp["direction"] == "IN":
        if gp["inward_kind"] == "RETURN_AGAINST_OUTWARD":
            linked = [i for i in items if i["source_outward_item_id"]]
            if not linked:
                errs.append({"field": "items", "label": "Items", "message": "Select the original outward gate pass items being returned"})
            pend = _pending_for_source(c, [str(i["source_outward_item_id"]) for i in linked])
            seen = {}
            for idx, i in enumerate(items):
                s = i["source_outward_item_id"]
                if not s:
                    continue
                pr = pend.get(str(s))
                if not pr:
                    errs.append({"item_index": idx, "message": "Original outward item is not open for return"}); continue
                if str(pr["unit_id"]) != str(i["unit_id"]):
                    errs.append({"item_index": idx, "message": "Unit must match the original outward item"})
                seen[str(s)] = seen.get(str(s), Decimal(0)) + i["quantity"]
                if seen[str(s)] > pr["qty_pending"]:
                    errs.append({"item_index": idx, "message": f"Returning {seen[str(s)]} exceeds the pending quantity {pr['qty_pending']}", "code": "RETURN_EXCEEDS_PENDING"})
    if errs:
        raise Invalid("The gate pass is incomplete", "VALIDATION_ERROR", errors=errs)
    return values, items


def submit(user, gp_id, row_version: int | None = None):
    with tx() as c:
        gp = load(c, gp_id, lock=True)
        if gp["created_by"] != user["id"]:
            raise NotFound("Gate pass")
        if "gatepass.submit" not in user["perms"]:
            raise Forbidden()
        if gp["status"] not in EDITABLE:
            raise Conflict("INVALID_TRANSITION", "Only drafts or rejected gate passes can be submitted")
        if row_version is not None and gp["row_version"] != row_version:
            raise Conflict("STALE_VERSION", "This gate pass was changed elsewhere. Reload and try again.")
        snap = _snapshot(c, gp)
        values, items = _validate_for_submit(c, gp, snap["snapshot"])
        first = gp["gate_pass_no"] is None
        now = scalar(c, "SELECT now()")
        number = format_number(c, now) if first else gp["gate_pass_no"]
        levels = scalar(c, "SELECT approval_levels FROM gate_pass_types WHERE id = :t", t=gp["type_id"])
        rev, rnd = gp["revision_no"] + 1, gp["round_no"] + 1
        resub = gp["status"] == "REJECTED"
        q(c, "UPDATE gate_passes SET gate_pass_no = :n, revision_no = :rev, round_no = :rnd, required_approval_levels = :l, submitted_at = :now, submitted_by = :u WHERE id = :g",
          n=number, rev=rev, rnd=rnd, l=levels, now=now, u=user["id"], g=gp["id"])
        gp.update(gate_pass_no=number, revision_no=rev, round_no=rnd)
        attachments = rows(c, "SELECT id, original_filename, kind FROM gate_pass_attachments WHERE gate_pass_id = :g AND status = 'READY' ORDER BY sequence_no", g=gp["id"])
        full = {"form_version": snap["version_no"], "header": values, "items": [formrt.item_values(snap["snapshot"], i) | {"id": str(i["id"]), "line_no": i["line_no"],
                "source_outward_item_id": str(i["source_outward_item_id"]) if i["source_outward_item_id"] else None} for i in items],
                "attachments": [{"id": str(a["id"]), "name": a["original_filename"], "kind": a["kind"]} for a in attachments]}
        js = json.dumps(full, sort_keys=True, default=jsonable)
        q(c, """INSERT INTO gate_pass_revisions (gate_pass_id, revision_no, reason, snapshot, snapshot_hash, created_by)
                VALUES (:g, :r, :why, CAST(:s AS jsonb), :h, :u)""", g=gp["id"], r=rev, why="RESUBMIT" if resub else "SUBMIT", s=js, h=hashlib.sha256(js.encode()).hexdigest(), u=user["id"])
        set_status(c, gp, "SUBMITTED", "Resubmitted after rejection" if resub else "Submitted", user["id"])
        if levels > 0:
            set_status(c, gp, "PENDING_L1", None, user["id"])
            perm = "approval.level1" if gp["direction"] == "OUT" else "inward.approve"
            nt.notify(c, nt.holders_of(c, perm), "approval_required", f"Approval required: {number}",
                      f"{user['full_name']} submitted {gp['type_code'].lower()} gate pass {number}. Please review it.", gp["id"],
                      {"gate_pass_no": number}, dedupe=f"approval_required:{gp['id']}:{rnd}:1", exclude=user["id"])
        else:
            set_status(c, gp, "APPROVED", "No approval required", user["id"], approved_at=now)
            nt.notify(c, nt.holders_of(c, "security.gateout" if gp["direction"] == "OUT" else "security.gatein"), "approved", f"Approved: {number}",
                      f"Gate pass {number} is approved and ready at the gate.", gp["id"], dedupe=f"approved:{gp['id']}:{rnd}")
        audit(c, "gatepass.submit", "gate_pass", gp["id"], f"Gate pass {number} submitted" + (" (resubmission)" if resub else ""), gate_pass_id=gp["id"],
              after={"number": number, "revision": rev, "round": rnd})
    return get_detail(user, gp_id)


def recall(user, gp_id):
    with tx() as c:
        gp = load(c, gp_id, lock=True)
        if gp["created_by"] != user["id"]:
            raise NotFound("Gate pass")
        if gp["status"] != "PENDING_L1" or scalar(c, "SELECT count(*) FROM gate_pass_approvals WHERE gate_pass_id = :g AND round_no = :r", g=gp["id"], r=gp["round_no"]):
            raise Conflict("INVALID_TRANSITION", "A gate pass can only be recalled while it waits for Level 1 and has no decision")
        set_status(c, gp, "DRAFT", "Recalled by creator", user["id"])
        audit(c, "gatepass.recall", "gate_pass", gp["id"], f"Gate pass {gp['gate_pass_no']} recalled to draft", gate_pass_id=gp["id"])
    return get_detail(user, gp_id)


def cancel(user, gp_id, reason: str):
    if not reason or not reason.strip():
        raise Invalid("A reason is required to cancel a gate pass", "REASON_REQUIRED")
    with tx() as c:
        gp = load(c, gp_id, lock=True)
        mine = gp["created_by"] == user["id"]
        if not ((mine and "gatepass.cancel" in user["perms"]) or "gatepass.cancel.any" in user["perms"]):
            if mine or "gatepass.view" in user["perms"]:
                raise Forbidden()
            raise NotFound("Gate pass")
        if gp["status"] not in CANCELLABLE:
            raise Conflict("INVALID_TRANSITION", "This gate pass can no longer be cancelled")
        set_status(c, gp, "CANCELLED", reason.strip(), user["id"], cancelled_at=scalar(c, "SELECT now()"), cancelled_by=user["id"], cancel_reason=reason.strip())
        if gp["gate_pass_no"]:
            nt.notify(c, [gp["created_by"]], "cancelled", f"Cancelled: {gp['gate_pass_no']}", f"Gate pass {gp['gate_pass_no']} was cancelled: {reason.strip()}", gp["id"],
                      dedupe=f"cancelled:{gp['id']}", exclude=user["id"])
        audit(c, "gatepass.cancel", "gate_pass", gp["id"], f"Gate pass {gp['gate_pass_no'] or 'draft'} cancelled", gate_pass_id=gp["id"],
              after={"reason": reason.strip()})
    return get_detail(user, gp_id)


# ---------------- read ----------------
def _actions(user, gp, approvals, has_gate_event, record):
    p, mine, st = user["perms"], gp["created_by"] == user["id"], gp["status"]
    a = {}
    a["edit"] = mine and "gatepass.edit" in p and st in EDITABLE
    a["submit"] = mine and "gatepass.submit" in p and st in EDITABLE
    a["recall"] = mine and st == "PENDING_L1" and not [x for x in approvals if x["round_no"] == gp["round_no"]]
    a["cancel"] = ((mine and "gatepass.cancel" in p) or "gatepass.cancel.any" in p) and st in CANCELLABLE
    lvl = {"PENDING_L1": 1, "PENDING_L2": 2}.get(st)
    can_dec = False
    if lvl:
        need = ("approval.level1" if lvl == 1 else "approval.level2") if gp["direction"] == "OUT" else "inward.approve"
        same_round = [x for x in approvals if x["round_no"] == gp["round_no"]]
        can_dec = need in p and (user["id"] != gp["created_by"] or ss.get("approval.allow_self_approval")) and \
            (not any(x["approver_id"] == user["id"] for x in same_round) or ss.get("approval.allow_same_user_both_levels"))
    a["approve"] = a["reject"] = can_dec
    a["gate_out"] = "security.gateout" in p and gp["direction"] == "OUT" and st == "APPROVED"
    a["gate_in"] = "security.gatein" in p and gp["direction"] == "IN" and st == "APPROVED"
    a["verify"] = "admin.verify" in p and has_gate_event
    a["writeoff"] = "return.writeoff" in p and record is not None and record["status"] in ("OPEN", "PARTIALLY_RETURNED")
    a["reverse"] = "return.close" in p and (record is not None or gp["direction"] == "IN") and has_gate_event
    a["move_to_latest_form"] = mine and st in EDITABLE
    a["pdf"] = st != "DRAFT" or mine
    a["upload"] = ("attachment.upload" in p) and ((mine and st in EDITABLE) or (st == "APPROVED" and (a["gate_out"] or a["gate_in"])))
    return a


def get_detail(user, gp_id):
    with tx() as c:
        check_visible(c, user, gp_id)
        gp = load(c, gp_id)
        snap = _snapshot(c, gp)
        latest = scalar(c, "SELECT current_version_id FROM form_definitions WHERE gate_pass_type_id = :t", t=gp["type_id"])
        items = rows(c, """SELECT i.*, u.code AS unit_code, u.decimal_places FROM gate_pass_items i JOIN units_of_measure u ON u.id = i.unit_id
                           WHERE i.gate_pass_id = :g ORDER BY i.line_no""", g=gp["id"])
        approvals = rows(c, "SELECT * FROM gate_pass_approvals WHERE gate_pass_id = :g ORDER BY decided_at", g=gp["id"])
        events = rows(c, """SELECT e.*, u.full_name AS recorded_by_name, g.name AS gate_name FROM gate_pass_gate_events e JOIN users u ON u.id = e.recorded_by
                            JOIN gates g ON g.id = e.gate_id WHERE e.gate_pass_id = :g ORDER BY e.occurred_at""", g=gp["id"])
        record = one(c, "SELECT * FROM returnable_records WHERE source_gate_pass_id = :g", g=gp["id"])
        ret_items = {}
        if record:
            for r in rows(c, "SELECT * FROM returnable_items WHERE record_id = :r", r=record["id"]):
                ret_items[str(r["source_item_id"])] = r
        out_items = []
        for it in items:
            d = {**it, "values": formrt.item_values(snap["snapshot"], it)}
            if str(it["id"]) in ret_items:
                r = ret_items[str(it["id"])]
                d["returnable"] = {"qty_out": r["qty_out"], "qty_returned": r["qty_returned"], "qty_adjusted": r["qty_adjusted"], "qty_pending": r["qty_pending"], "status": r["status"], "returnable_item_id": r["id"]}
            out_items.append(d)
        creator = one(c, "SELECT full_name, username FROM users WHERE id = :u", u=gp["created_by"])
        loc = one(c, "SELECT id, code, name FROM locations WHERE id = :l", l=gp["location_id"]) if gp["location_id"] else None
        dept = one(c, "SELECT id, name FROM departments WHERE id = :d", d=gp["department_id"]) if gp["department_id"] else None
        resp = gp["responsible_name"] or (scalar(c, "SELECT full_name FROM users WHERE id = :u", u=gp["responsible_user_id"]) if gp["responsible_user_id"] else None)
        attachments = rows(c, """SELECT a.id, a.kind, a.stage, a.sequence_no, a.original_filename, a.detected_mime, a.size_bytes, a.status, a.gate_pass_item_id, a.uploaded_at,
                                 a.thumbnail_key IS NOT NULL AS has_thumbnail, u.full_name AS uploaded_by_name FROM gate_pass_attachments a
                                 JOIN users u ON u.id = a.uploaded_by WHERE a.gate_pass_id = :g AND a.status <> 'DELETED' ORDER BY a.sequence_no""", g=gp["id"])
        links = {}
        if gp["direction"] == "IN":
            links["returns_against"] = rows(c, """SELECT DISTINCT o.id, o.gate_pass_no FROM gate_pass_items i JOIN gate_pass_items oi ON oi.id = i.source_outward_item_id
                                                JOIN gate_passes o ON o.id = oi.gate_pass_id WHERE i.gate_pass_id = :g""", g=gp["id"])
        else:
            links["returned_by"] = rows(c, """SELECT DISTINCT ip.id, ip.gate_pass_no, ip.status FROM returnable_transactions rt JOIN gate_passes ip ON ip.id = rt.inward_gate_pass_id
                                            JOIN returnable_items ri ON ri.id = rt.returnable_item_id JOIN returnable_records rr ON rr.id = ri.record_id
                                            WHERE rr.source_gate_pass_id = :g AND rt.txn_type = 'RETURN'""", g=gp["id"])
        verifs = rows(c, "SELECT v.*, u.full_name AS verified_by_name FROM gate_pass_verifications v JOIN users u ON u.id = v.verified_by WHERE v.gate_pass_id = :g ORDER BY verified_at DESC", g=gp["id"])
        d = {k: v for k, v in gp.items() if k not in ("custom_data",)}
        d.update(type=gp["type_code"], direction=gp["direction"], created_by_name=creator["full_name"], location=loc, department=dept, responsible_display=resp,
                 values=formrt.header_values(snap["snapshot"], gp), items=out_items, approvals=approvals, gate_events=events, verifications=verifs,
                 attachments=attachments, form_version_no=snap["version_no"], form_snapshot=snap["snapshot"], newer_form_available=str(latest) != str(gp["form_version_id"]),
                 return_record={**record} if record else None, links=links,
                 actions=_actions(user, gp, approvals, bool(events), record),
                 history=rows(c, """SELECT h.id, h.from_status, h.to_status, h.reason, h.occurred_at, h.revision_no, h.round_no, u.full_name AS actor
                                    FROM gate_pass_status_history h LEFT JOIN users u ON u.id = h.actor_id WHERE h.gate_pass_id = :g ORDER BY h.id""", g=gp["id"]))
        return d


SORTS = {"created_at": "g.created_at", "submitted_at": "g.submitted_at", "gate_pass_no": "g.gate_pass_no", "status": "g.status", "expected_return_date": "g.expected_return_date",
         "reference_no": "g.reference_no", "vehicle_no": "g.vehicle_no"}


def search(user, pg: Page, f: dict):
    w, p = visibility_sql(user)
    where = [w]
    if f.get("q"):
        p["q"] = f"%{f['q'].strip()}%"
        p["qn"] = f"%{re.sub(r'[^A-Za-z0-9]', '', f['q']).upper()}%"
        where.append("""(g.gate_pass_no ILIKE :q OR g.reference_no ILIKE :q OR g.vehicle_no_normalized LIKE :qn OR g.seal_no ILIKE :q OR l.name ILIKE :q OR g.responsible_name ILIKE :q
                         OR ru.full_name ILIKE :q OR cu.full_name ILIKE :q OR EXISTS (SELECT 1 FROM gate_pass_items i WHERE i.gate_pass_id = g.id AND (i.description ILIKE :q OR i.item_code ILIKE :q)))""")
    if f.get("type"):
        where.append("t.code = :type"); p["type"] = f["type"].upper()
    if f.get("status"):
        where.append("g.status = ANY(:status)"); p["status"] = [s.upper() for s in f["status"]]
    if f.get("returnable") is not None:
        where.append("g.has_returnable = :ret"); p["ret"] = f["returnable"]
    if f.get("return_status"):
        where.append("rr.status = :rs"); p["rs"] = f["return_status"].upper()
    if f.get("overdue"):
        where.append("rr.status IN ('OPEN','PARTIALLY_RETURNED') AND rr.expected_return_date < :today"); p["today"] = today_local()
    for k, col in (("location_id", "g.location_id"), ("department_id", "g.department_id"), ("created_by", "g.created_by"), ("responsible_user_id", "g.responsible_user_id")):
        if f.get(k):
            where.append(f"{col} = CAST(:{k} AS uuid)"); p[k] = f[k]
    if f.get("date_from"):
        where.append("(g.created_at AT TIME ZONE :tz)::date >= :df"); p["df"] = f["date_from"]; p["tz"] = settings.timezone
    if f.get("date_to"):
        where.append("(g.created_at AT TIME ZONE :tz)::date <= :dt"); p["dt"] = f["date_to"]; p["tz"] = settings.timezone
    if f.get("mine"):
        where.append("g.created_by = :v_uid")
    if f.get("drafts"):
        where.append("g.status = 'DRAFT' AND g.created_by = :v_uid")
    if f.get("pending_my_approval"):
        conds = []
        if "approval.level1" in user["perms"]:
            conds.append("(t.code = 'OUTWARD' AND g.status = 'PENDING_L1')")
        if "approval.level2" in user["perms"]:
            conds.append("(t.code = 'OUTWARD' AND g.status = 'PENDING_L2')")
        if "inward.approve" in user["perms"]:
            conds.append("(t.code = 'INWARD' AND g.status = 'PENDING_L1')")
        where.append("(" + " OR ".join(conds) + ") AND g.created_by <> :v_uid" if conds else "FALSE")
    sort = SORTS.get(f.get("sort") or "created_at", "g.created_at")
    direction = "ASC" if f.get("order") == "asc" else "DESC"
    base = f"""FROM gate_passes g JOIN gate_pass_types t ON t.id = g.type_id LEFT JOIN locations l ON l.id = g.location_id
               LEFT JOIN users cu ON cu.id = g.created_by LEFT JOIN users ru ON ru.id = g.responsible_user_id
               LEFT JOIN returnable_records rr ON rr.source_gate_pass_id = g.id WHERE {' AND '.join(where)}"""
    with tx() as c:
        total = scalar(c, f"SELECT count(*) {base}", **p)
        items = rows(c, f"""SELECT g.id, g.gate_pass_no, t.code AS type, g.status, g.reference_no, g.vehicle_no, g.seal_no, l.name AS location, g.created_at, g.submitted_at,
                            g.planned_datetime, g.has_returnable, g.expected_return_date, cu.full_name AS created_by_name,
                            coalesce(g.responsible_name, ru.full_name) AS responsible, rr.status AS return_status,
                            (rr.status IN ('OPEN','PARTIALLY_RETURNED') AND rr.expected_return_date < :today) AS overdue,
                            (SELECT count(*) FROM gate_pass_items i WHERE i.gate_pass_id = g.id) AS items_count
                            {base} ORDER BY {sort} {direction} NULLS LAST, g.id LIMIT :lim OFFSET :off""", lim=pg.size, off=pg.offset, **{**p, "today": today_local()})
        return envelope(items, total, pg)


def timeline(user, gp_id):
    d = get_detail(user, gp_id)
    ev = [{"at": h["occurred_at"], "type": "status", "text": f"{h['from_status'] or '—'} → {h['to_status']}", "actor": h["actor"], "reason": h["reason"]} for h in d["history"]]
    ev += [{"at": a["decided_at"], "type": "approval", "text": f"Level {a['level']} {a['decision'].lower()} (round {a['round_no']})", "actor": a["approver_name"], "reason": a["comments"]} for a in d["approvals"]]
    ev += [{"at": e["occurred_at"], "type": "gate", "text": e["event_type"].replace("_", " ").title(), "actor": e["recorded_by_name"], "reason": e["remarks"]} for e in d["gate_events"]]
    ev += [{"at": v["verified_at"], "type": "verification", "text": f"Admin/Audit {v['result'].lower()}", "actor": v["verified_by_name"], "reason": v["notes"]} for v in d["verifications"]]
    with tx() as c:
        for a in rows(c, "SELECT occurred_at, action, summary, actor_username FROM audit_logs WHERE gate_pass_id = :g AND action IN ('gatepass.update','attachment.confirm','attachment.delete','return.post','return.adjust','return.reverse') ORDER BY id", g=d["id"]):
            ev.append({"at": a["occurred_at"], "type": "audit", "text": a["summary"], "actor": a["actor_username"], "reason": None})
    return sorted(ev, key=lambda e: e["at"])
