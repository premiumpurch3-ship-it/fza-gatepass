"""Approvals, security gate events, return reconciliation (ledger), write-off, reversal, reminders, admin verification."""
from datetime import timedelta
from decimal import Decimal

from ..core import ctx, settings_store as ss
from ..core.audit import audit
from ..core.db import J, one, q, rows, scalar, tx
from ..core.errors import AppError, Conflict, Forbidden, Invalid, NotFound
from . import gatepass as gp_svc, notifications as nt


# ======================= APPROVALS =======================
def _decide(user, gp_id, decision: str, comments: str | None, level: int | None):
    with tx() as c:
        gp = gp_svc.load(c, gp_id, lock=True)
        st = gp["status"]
        lvl = {"PENDING_L1": 1, "PENDING_L2": 2}.get(st)
        if not lvl:
            # hide existence from users with no business seeing it
            gp_svc.check_visible(c, user, gp_id)
            raise Conflict("INVALID_TRANSITION", "This gate pass is not waiting for approval")
        if level is not None and level != lvl:
            raise Conflict("WRONG_LEVEL", f"This gate pass is waiting for level {lvl} approval")
        need = ("approval.level1" if lvl == 1 else "approval.level2") if gp["direction"] == "OUT" else "inward.approve"
        if need not in user["perms"]:
            raise Forbidden("You are not authorised to approve at this level")
        if str(gp["created_by"]) == str(user["id"]) and not ss.get("approval.allow_self_approval", c):
            raise Forbidden("You cannot approve or reject a gate pass you created", "SELF_APPROVAL_FORBIDDEN")
        prior = rows(c, "SELECT level, approver_id, decision FROM gate_pass_approvals WHERE gate_pass_id = :g AND round_no = :r", g=gp["id"], r=gp["round_no"])
        if lvl == 2 and not any(p["level"] == 1 and p["decision"] == "APPROVED" for p in prior):
            raise Conflict("LEVEL1_REQUIRED", "Level 2 approval requires Level 1 approval first")
        if any(str(p["approver_id"]) == str(user["id"]) for p in prior) and not ss.get("approval.allow_same_user_both_levels", c):
            raise Forbidden("The same person cannot approve both levels of one gate pass", "SAME_APPROVER_FORBIDDEN")
        if decision == "REJECTED" and not (comments or "").strip():
            raise Invalid("A reason is required to reject", "REASON_REQUIRED")
        if decision == "APPROVED" and ss.get("approval.require_comment_on_approve", c) and not (comments or "").strip():
            raise Invalid("A comment is required", "REASON_REQUIRED")
        r = ctx.get()
        q(c, """INSERT INTO gate_pass_approvals (gate_pass_id, round_no, revision_no, level, approver_id, approver_name, approver_was_master_admin, decision, comments,
                ip, user_agent, platform, client_version, device_info) VALUES (:g, :rnd, :rev, :lvl, :u, :nm, :ma, :d, :cm, CAST(:ip AS inet), :ua, :pl, :cv, CAST(:di AS jsonb))""",
          g=gp["id"], rnd=gp["round_no"], rev=gp["revision_no"], lvl=lvl, u=user["id"], nm=user["full_name"], ma=bool(user["is_master_admin"]), d=decision,
          cm=(comments or "").strip() or None, ip=r.ip, ua=(r.user_agent or "")[:300], pl=r.platform, cv=r.client_version, di=J({"user_agent": (r.user_agent or "")[:200]}))
        num = gp["gate_pass_no"]
        if decision == "REJECTED":
            set_ = gp_svc.set_status
            set_(c, gp, "REJECTED", comments.strip(), user["id"], last_rejected_at=scalar(c, "SELECT now()"), last_rejected_by=user["id"], last_rejection_reason=comments.strip())
            nt.notify(c, [gp["created_by"]], "rejected", f"Rejected: {num}", f"Gate pass {num} was rejected at level {lvl} by {user['full_name']}: {comments.strip()}",
                      gp["id"], dedupe=f"rejected:{gp['id']}:{gp['round_no']}")
            audit(c, "gatepass.reject", "gate_pass", gp["id"], f"Gate pass {num} rejected at level {lvl}", gate_pass_id=gp["id"],
                  after={"level": lvl, "reason": comments.strip(), "master_admin": bool(user["is_master_admin"])})
        else:
            gp_svc.set_status(c, gp, "L1_APPROVED" if lvl == 1 else "APPROVED", comments, user["id"],
                              **({"approved_at": scalar(c, "SELECT now()")} if lvl == 2 else {}))
            if lvl == 1:
                if gp["required_approval_levels"] >= 2:
                    gp_svc.set_status(c, gp, "PENDING_L2", None, user["id"])
                    nt.notify(c, nt.holders_of(c, "approval.level2"), "approval_required", f"Level 2 approval required: {num}",
                              f"Gate pass {num} passed Level 1 and needs your approval.", gp["id"], dedupe=f"approval_required:{gp['id']}:{gp['round_no']}:2", exclude=user["id"])
                else:
                    gp_svc.set_status(c, gp, "APPROVED", None, user["id"], approved_at=scalar(c, "SELECT now()"))
            if gp["status"] == "APPROVED":
                perm = "security.gateout" if gp["direction"] == "OUT" else "security.gatein"
                nt.notify(c, [gp["created_by"]] + nt.holders_of(c, perm), "approved", f"Approved: {num}",
                          f"Gate pass {num} is fully approved and ready at the gate.", gp["id"], dedupe=f"approved:{gp['id']}:{gp['round_no']}")
            else:
                nt.notify(c, [gp["created_by"]], "approval_completed", f"Level {lvl} approved: {num}", f"{user['full_name']} approved gate pass {num} at level {lvl}.",
                          gp["id"], dedupe=f"approval_completed:{gp['id']}:{gp['round_no']}:{lvl}")
            audit(c, f"gatepass.approve.l{lvl}", "gate_pass", gp["id"], f"Gate pass {num} approved at level {lvl}", gate_pass_id=gp["id"],
                  after={"level": lvl, "master_admin": bool(user["is_master_admin"])})
    return gp_svc.get_detail(user, gp_id)


def approve(user, gp_id, comments=None, level=None):
    return _decide(user, gp_id, "APPROVED", comments, level)


def reject(user, gp_id, reason, level=None):
    return _decide(user, gp_id, "REJECTED", reason, level)


def pending_queue(user, pg):
    return gp_svc.search(user, pg, {"pending_my_approval": True, "sort": "submitted_at", "order": "asc"})


# ======================= RETURN LEDGER HELPERS =======================
def _move_pass(c, gp, target: str, actor_id, reason=None, **cols):
    """Move a (returnable) outward pass along allowed transitions to `target`."""
    cur = gp["status"]
    if cur == target:
        return
    if target == "CLOSED":
        if cur != "COMPLETED":
            gp_svc.set_status(c, gp, "COMPLETED", reason, actor_id, completed_at=scalar(c, "SELECT now()"))
        gp_svc.set_status(c, gp, "CLOSED", reason, actor_id, closed_at=scalar(c, "SELECT now()"), **cols)
    else:
        extra = {"completed_at": scalar(c, "SELECT now()")} if target == "COMPLETED" else {}
        gp_svc.set_status(c, gp, target, reason, actor_id, **extra)


def recompute_record(c, record_id, actor_id, reason=None, closing_user=None):
    rec = one(c, "SELECT * FROM returnable_records WHERE id = :r FOR UPDATE", r=record_id)
    its = rows(c, "SELECT qty_pending, qty_returned, qty_adjusted FROM returnable_items WHERE record_id = :r", r=record_id)
    any_moved = any(i["qty_returned"] + i["qty_adjusted"] > 0 for i in its)
    all_zero = all(i["qty_pending"] == 0 for i in its)
    adjusted = any(i["qty_adjusted"] > 0 for i in its)
    new = "OPEN" if not any_moved else ("PARTIALLY_RETURNED" if not all_zero else ("CLOSED_ADJUSTED" if adjusted else "COMPLETED"))
    if new != rec["status"] or True:
        if new == "COMPLETED":
            q(c, "UPDATE returnable_records SET status = 'COMPLETED', completed_at = COALESCE(completed_at, now()), closed_at = NULL, closed_by = NULL, close_reason = NULL WHERE id = :r", r=record_id)
        elif new == "CLOSED_ADJUSTED":
            q(c, "UPDATE returnable_records SET status = 'CLOSED_ADJUSTED', completed_at = COALESCE(completed_at, now()), closed_at = now(), closed_by = :u, close_reason = :why WHERE id = :r",
              u=closing_user or actor_id, why=reason or rec["close_reason"] or "Closed", r=record_id)
        else:
            q(c, "UPDATE returnable_records SET status = :s, completed_at = NULL, closed_at = NULL, closed_by = NULL, close_reason = NULL WHERE id = :r", s=new, r=record_id)
    gp = gp_svc.load(c, rec["source_gate_pass_id"], lock=True)
    auto = ss.get("workflow.auto_close_after_complete", c)
    if new == "OPEN":
        target = "PENDING_RETURN"
    elif new == "PARTIALLY_RETURNED":
        target = "PARTIALLY_RETURNED"
    else:
        target = "CLOSED" if (auto or new == "CLOSED_ADJUSTED") else "COMPLETED"
    if gp["status"] == "CLOSED" and target == "COMPLETED":
        target = "CLOSED"
    _move_pass(c, gp, target, actor_id, reason or {"PENDING_RETURN": "Return reopened", "PARTIALLY_RETURNED": "Partial return", "COMPLETED": "All returned", "CLOSED": "All returned"}.get(target),
               **({"closed_by": closing_user} if closing_user and target == "CLOSED" else {}))
    return new, gp


def _create_record(c, gp, event_at, items_verified: list[dict]):
    rec = one(c, """INSERT INTO returnable_records (source_gate_pass_id, expected_return_date, opened_at) VALUES (:g, :d, :t) RETURNING id""",
              g=gp["id"], d=gp["expected_return_date"], t=event_at)
    for it in items_verified:
        q(c, "INSERT INTO returnable_items (record_id, source_item_id, unit_id, qty_out) VALUES (:r, :i, :u, :q)", r=rec["id"], i=it["id"], u=it["unit_id"], q=it["verified"])
    return rec["id"]


# ======================= GATE OUT =======================
def _resolve_gate(c, gate_id):
    if gate_id:
        g = one(c, "SELECT id FROM gates WHERE id = CAST(:g AS uuid) AND is_active", g=gate_id)
        if not g:
            raise Invalid("Unknown or inactive gate", "VALIDATION_ERROR")
        return g["id"]
    gs = rows(c, "SELECT id FROM gates WHERE is_active")
    if len(gs) != 1:
        raise Invalid("Select the gate", "GATE_REQUIRED")
    return gs[0]["id"]


def _norm(s):
    return "".join(ch for ch in (s or "").upper() if ch.isalnum())


def _event_common(c, user, gp, event_type, body, verified_map, discrepancy):
    r = ctx.get()
    gate = _resolve_gate(c, body.get("gate_id"))
    veh_mismatch = bool(body.get("vehicle_no_verified")) and bool(gp["vehicle_no"]) and _norm(body["vehicle_no_verified"]) != _norm(gp["vehicle_no"])
    seal_mismatch = bool(body.get("seal_no_verified")) and bool(gp["seal_no"]) and _norm(body["seal_no_verified"]) != _norm(gp["seal_no"])
    disc = discrepancy or veh_mismatch or seal_mismatch or body.get("seal_intact") is False
    ev = one(c, """INSERT INTO gate_pass_gate_events (gate_pass_id, event_type, gate_id, recorded_by, vehicle_no_verified, seal_no_verified, seal_intact, driver_name, remarks,
                   has_discrepancy, ip, platform, device_info) VALUES (:g, :t, :gate, :u, :vv, :sv, :si, :dn, :rm, :d, CAST(:ip AS inet), :pl, CAST(:di AS jsonb)) RETURNING id, occurred_at""",
             g=gp["id"], t=event_type, gate=gate, u=user["id"], vv=body.get("vehicle_no_verified"), sv=body.get("seal_no_verified"), si=body.get("seal_intact"),
             dn=body.get("driver_name"), rm=(body.get("remarks") or "").strip() or None, d=disc, ip=r.ip, pl=r.platform, di=J({"user_agent": (r.user_agent or "")[:200]}))
    return ev, disc


def _verified_for(items, body, allow_over: bool):
    given = {str(i["id"]): i for i in (body.get("items") or [])}
    unknown = set(given) - {str(i["id"]) for i in items}
    if unknown:
        raise Invalid("Unknown item in verification", "VALIDATION_ERROR")
    out = {}
    for it in items:
        g = given.get(str(it["id"]), {})
        v = g.get("verified_quantity")
        v = it["quantity"] if v is None else Decimal(str(v))
        if v < 0:
            raise Invalid("Verified quantity cannot be negative", "VALIDATION_ERROR")
        if not allow_over and v > it["quantity"]:
            raise Invalid(f"Verified quantity for '{it['description']}' exceeds the approved quantity {it['quantity']}", "OVER_APPROVED_QUANTITY")
        out[str(it["id"])] = (v, g.get("condition_value"))
    return out


def gate_out(user, gp_id, body: dict):
    with tx() as c:
        gp = gp_svc.load(c, gp_id, lock=True)
        if "security.gateout" not in user["perms"]:
            raise Forbidden()
        if gp["direction"] != "OUT":
            raise Conflict("INVALID_TRANSITION", "Gate Out applies to outward gate passes only")
        if gp["status"] != "APPROVED":
            raise Conflict("INVALID_TRANSITION", "Gate Out requires a fully approved gate pass")
        items = rows(c, "SELECT * FROM gate_pass_items WHERE gate_pass_id = :g ORDER BY line_no FOR UPDATE", g=gp["id"])
        ver = _verified_for(items, body, allow_over=False)
        disc = any(ver[str(i["id"])][0] != i["quantity"] for i in items)
        ev, disc = _event_common(c, user, gp, "GATE_OUT", body, ver, disc)
        for i in items:
            q(c, "UPDATE gate_pass_items SET verified_quantity = :v WHERE id = :i", v=ver[str(i["id"])][0], i=i["id"])
        gp_svc.set_status(c, gp, "GATE_OUT", body.get("remarks"), user["id"])
        ret_lines = [{"id": i["id"], "unit_id": i["unit_id"], "verified": ver[str(i["id"])][0]} for i in items if i["is_returnable"] and ver[str(i["id"])][0] > 0]
        if ret_lines:
            _create_record(c, gp, ev["occurred_at"], ret_lines)
            gp_svc.set_status(c, gp, "PENDING_RETURN", "Returnable tracking opened", user["id"])
        else:
            _move_pass(c, gp, "CLOSED" if ss.get("workflow.auto_close_after_complete", c) else "COMPLETED", user["id"], "Gate Out completed (no returnable items)")
        nt.notify(c, [gp["created_by"]], "gate_out", f"Gate Out: {gp['gate_pass_no']}", f"Gate pass {gp['gate_pass_no']} left the gate (recorded by {user['full_name']}).",
                  gp["id"], dedupe=f"gate_out:{gp['id']}")
        audit(c, "gatepass.gate_out", "gate_pass", gp["id"], f"Gate Out recorded for {gp['gate_pass_no']}", gate_pass_id=gp["id"],
              after={"discrepancy": disc, "gate_event_id": ev["id"]}, severity="WARN" if disc else "INFO")
    return gp_svc.get_detail(user, gp_id)


# ======================= GATE IN (return posting) =======================
def gate_in(user, gp_id, body: dict):
    with tx() as c:
        gp = gp_svc.load(c, gp_id, lock=True)
        if "security.gatein" not in user["perms"]:
            raise Forbidden()
        if gp["direction"] != "IN":
            raise Conflict("INVALID_TRANSITION", "Gate In applies to inward gate passes only")
        if gp["status"] != "APPROVED":
            raise Conflict("INVALID_TRANSITION", "Gate In requires a fully approved inward gate pass")
        items = rows(c, "SELECT * FROM gate_pass_items WHERE gate_pass_id = :g ORDER BY line_no FOR UPDATE", g=gp["id"])
        ver = _verified_for(items, body, allow_over=True)
        linked = [i for i in items if i["source_outward_item_id"]]
        # lock order: returnable_items by id ASC (prevents deadlocks between concurrent gate-ins); then records ASC; then outward passes ASC
        ri = {str(r["source_item_id"]): r for r in rows(c, """SELECT * FROM returnable_items WHERE source_item_id = ANY(CAST(:s AS uuid[])) ORDER BY id FOR UPDATE""",
                                                         s=[str(i["source_outward_item_id"]) for i in linked])}
        disc = gp["inward_kind"] == "RETURN_AGAINST_OUTWARD" and any(not i["source_outward_item_id"] for i in items)
        posted, records = [], set()
        for i in sorted(linked, key=lambda x: x["line_no"]):
            v = ver[str(i["id"])][0]
            if v != i["quantity"]:
                disc = True
            r = ri.get(str(i["source_outward_item_id"]))
            if not r:
                raise Conflict("NOT_RETURNABLE", f"Item {i['line_no']} does not refer to an open returnable item")
            if str(r["unit_id"]) != str(i["unit_id"]):
                raise Conflict("UNIT_MISMATCH", f"Unit of item {i['line_no']} differs from the outward item")
            if v == 0:
                continue
            pending = scalar(c, "SELECT qty_pending FROM returnable_items WHERE id = :i", i=r["id"])
            if v > pending:       # D-04: never accept more than pending (also protected by CHECK ck_ri__no_overreturn)
                raise Conflict("RETURN_EXCEEDS_PENDING", f"Cannot receive {v}: only {pending} is pending for item {i['line_no']}",
                               line_no=i["line_no"], pending=str(pending), attempted=str(v))
            q(c, "UPDATE returnable_items SET qty_returned = qty_returned + :v, row_version = row_version + 1 WHERE id = :i", v=v, i=r["id"])
            q(c, """INSERT INTO returnable_transactions (returnable_item_id, txn_type, quantity, inward_gate_pass_id, inward_item_id, condition_value, recorded_by)
                    VALUES (:r, 'RETURN', :v, :g, :ii, :cv, :u)""", r=r["id"], v=v, g=gp["id"], ii=i["id"], cv=ver[str(i["id"])][1], u=user["id"])
            records.add(str(r["record_id"]))
            posted.append({"line_no": i["line_no"], "quantity": str(v)})
        ev, disc = _event_common(c, user, gp, "GATE_IN", body, ver, disc)
        for i in items:
            q(c, "UPDATE gate_pass_items SET verified_quantity = :v, verified_condition_value = :cv WHERE id = :i", v=ver[str(i["id"])][0], cv=ver[str(i["id"])][1], i=i["id"])
        gp_svc.set_status(c, gp, "GATE_IN", body.get("remarks"), user["id"])
        _move_pass(c, gp, "CLOSED" if ss.get("workflow.auto_close_after_complete", c) else "COMPLETED", user["id"], "Gate In completed")
        outward_nums = []
        for rid in sorted(records):
            new, ogp = recompute_record(c, rid, user["id"], reason=f"Return received via {gp['gate_pass_no']}")
            outward_nums.append(ogp["gate_pass_no"])
            nt.notify(c, [ogp["created_by"]], "gate_in", f"Return received: {ogp['gate_pass_no']}",
                      f"Items of {ogp['gate_pass_no']} were received at the gate via {gp['gate_pass_no']} (status: {new.replace('_', ' ').title()}).", ogp["id"],
                      dedupe=f"gate_in:{ogp['id']}:{gp['id']}")
        for p in posted:
            audit(c, "return.post", "gate_pass", gp["id"], f"Return posted on {gp['gate_pass_no']} line {p['line_no']}: {p['quantity']}", gate_pass_id=gp["id"], after=p)
        nt.notify(c, [gp["created_by"]], "gate_in", f"Gate In: {gp['gate_pass_no']}", f"Gate pass {gp['gate_pass_no']} was received at the gate.", gp["id"], dedupe=f"gate_in:{gp['id']}")
        audit(c, "gatepass.gate_in", "gate_pass", gp["id"], f"Gate In recorded for {gp['gate_pass_no']}", gate_pass_id=gp["id"],
              after={"discrepancy": disc, "returns_posted": posted, "outward": outward_nums}, severity="WARN" if disc else "INFO")
    return gp_svc.get_detail(user, gp_id)


# ======================= RETURNS (tracking, write-off, reversal) =======================
def returns_list(user, pg, f: dict):
    if "return.view" not in user["perms"]:
        raise Forbidden()
    where, p = ["TRUE"], {"today": gp_svc.today_local()}
    if f.get("status"):
        where.append("rr.status = :st"); p["st"] = f["status"].upper()
    if f.get("overdue"):
        where.append("rr.status IN ('OPEN','PARTIALLY_RETURNED') AND rr.expected_return_date < :today")
    if f.get("outstanding"):
        where.append("rr.status IN ('OPEN','PARTIALLY_RETURNED')")
    if f.get("location_id"):
        where.append("g.location_id = CAST(:loc AS uuid)"); p["loc"] = f["location_id"]
    if f.get("responsible_user_id"):
        where.append("g.responsible_user_id = CAST(:ru AS uuid)"); p["ru"] = f["responsible_user_id"]
    if f.get("q"):
        where.append("(g.gate_pass_no ILIKE :q OR g.reference_no ILIKE :q OR EXISTS (SELECT 1 FROM gate_pass_items i WHERE i.gate_pass_id = g.id AND i.description ILIKE :q))")
        p["q"] = f"%{f['q']}%"
    if f.get("date_from"):
        where.append("rr.expected_return_date >= :df"); p["df"] = f["date_from"]
    if f.get("date_to"):
        where.append("rr.expected_return_date <= :dt"); p["dt"] = f["date_to"]
    base = f"""FROM returnable_records rr JOIN gate_passes g ON g.id = rr.source_gate_pass_id LEFT JOIN locations l ON l.id = g.location_id
               LEFT JOIN users ru ON ru.id = g.responsible_user_id WHERE {' AND '.join(where)}"""
    with tx() as c:
        from ..core.paging import envelope
        total = scalar(c, f"SELECT count(*) {base}", **{k: v for k, v in p.items() if k != "today" or "overdue" in f or True})
        items = rows(c, f"""SELECT rr.id AS record_id, g.id AS gate_pass_id, g.gate_pass_no, g.reference_no, l.name AS location, coalesce(g.responsible_name, ru.full_name) AS responsible,
                            rr.status, rr.expected_return_date, rr.opened_at,
                            (rr.status IN ('OPEN','PARTIALLY_RETURNED') AND rr.expected_return_date < :today) AS overdue,
                            GREATEST(0, :today - rr.expected_return_date) AS days_overdue,
                            (SELECT coalesce(sum(qty_out),0) FROM returnable_items WHERE record_id = rr.id) AS qty_out,
                            (SELECT coalesce(sum(qty_returned),0) FROM returnable_items WHERE record_id = rr.id) AS qty_returned,
                            (SELECT coalesce(sum(qty_adjusted),0) FROM returnable_items WHERE record_id = rr.id) AS qty_adjusted,
                            (SELECT coalesce(sum(qty_pending),0) FROM returnable_items WHERE record_id = rr.id) AS qty_pending
                            {base} ORDER BY rr.expected_return_date, g.gate_pass_no LIMIT :lim OFFSET :off""", lim=pg.size, off=pg.offset, **p)
        return envelope(items, total, pg)


def return_detail(user, record_id):
    if "return.view" not in user["perms"]:
        raise Forbidden()
    with tx() as c:
        rr = one(c, """SELECT rr.*, g.gate_pass_no, g.id AS gate_pass_id, g.reference_no, g.status AS gate_pass_status, l.name AS location,
                       coalesce(g.responsible_name, ru.full_name) AS responsible FROM returnable_records rr JOIN gate_passes g ON g.id = rr.source_gate_pass_id
                       LEFT JOIN locations l ON l.id = g.location_id LEFT JOIN users ru ON ru.id = g.responsible_user_id WHERE rr.id = :r""", r=record_id)
        if not rr:
            raise NotFound("Return record")
        rr["overdue"] = rr["status"] in ("OPEN", "PARTIALLY_RETURNED") and rr["expected_return_date"] < gp_svc.today_local()
        rr["items"] = rows(c, """SELECT ri.*, i.description, i.item_code, i.line_no, u.code AS unit_code FROM returnable_items ri JOIN gate_pass_items i ON i.id = ri.source_item_id
                                 JOIN units_of_measure u ON u.id = ri.unit_id WHERE ri.record_id = :r ORDER BY i.line_no""", r=record_id)
        for it in rr["items"]:
            it["history"] = rows(c, """SELECT t.id, t.txn_type, t.quantity, t.reason, t.condition_value, t.recorded_at, u.full_name AS recorded_by, ig.gate_pass_no AS inward_no,
                                      ig.id AS inward_gate_pass_id, t.reverses_txn_id, (SELECT 1 FROM returnable_transactions x WHERE x.reverses_txn_id = t.id) IS NOT NULL AS reversed
                                      FROM returnable_transactions t JOIN users u ON u.id = t.recorded_by LEFT JOIN gate_passes ig ON ig.id = t.inward_gate_pass_id
                                      WHERE t.returnable_item_id = :i ORDER BY t.recorded_at""", i=it["id"])
        return rr


def writeoff(user, gp_id, reason: str, lines: list[dict] | None):
    """D-05: only holders of return.writeoff (Admin/Audit, Master Admin) – mandatory reason – audited – no silent closure."""
    if "return.writeoff" not in user["perms"]:
        raise Forbidden("Only Admin/Audit or the Master Admin may write off unreturned items")
    if not reason or not reason.strip():
        raise Invalid("A reason is required to close or write off unreturned items", "REASON_REQUIRED")
    with tx() as c:
        gp = gp_svc.load(c, gp_id, lock=True)
        rec = one(c, "SELECT * FROM returnable_records WHERE source_gate_pass_id = :g FOR UPDATE", g=gp["id"])
        if not rec or rec["status"] not in ("OPEN", "PARTIALLY_RETURNED"):
            raise Conflict("INVALID_TRANSITION", "There is nothing pending to write off for this gate pass")
        its = rows(c, "SELECT * FROM returnable_items WHERE record_id = :r AND qty_pending > 0 ORDER BY id FOR UPDATE", r=rec["id"])
        want = {str(l["returnable_item_id"]): Decimal(str(l["quantity"])) for l in lines} if lines else {str(i["id"]): i["qty_pending"] for i in its}
        done = []
        for it in its:
            qty = want.get(str(it["id"]))
            if qty is None:
                continue
            if qty <= 0 or qty > it["qty_pending"]:
                raise Invalid(f"Write-off quantity must be between 0 and the pending quantity {it['qty_pending']}", "VALIDATION_ERROR")
            q(c, "UPDATE returnable_items SET qty_adjusted = qty_adjusted + :v, row_version = row_version + 1 WHERE id = :i", v=qty, i=it["id"])
            q(c, "INSERT INTO returnable_transactions (returnable_item_id, txn_type, quantity, reason, recorded_by) VALUES (:i, 'ADJUSTMENT', :v, :r, :u)",
              i=it["id"], v=qty, r=reason.strip(), u=user["id"])
            done.append({"returnable_item_id": str(it["id"]), "quantity": str(qty)})
        if not done:
            raise Invalid("No matching pending lines", "VALIDATION_ERROR")
        new, ogp = recompute_record(c, rec["id"], user["id"], reason=reason.strip(), closing_user=user["id"])
        audit(c, "return.adjust", "gate_pass", gp["id"], f"Unreturned quantity written off on {gp['gate_pass_no']}", gate_pass_id=gp["id"],
              after={"reason": reason.strip(), "lines": done, "record_status": new, "master_admin": bool(user["is_master_admin"])}, severity="WARN")
        nt.notify(c, [gp["created_by"]], "closed_writeoff", f"Return closed / written off: {gp['gate_pass_no']}",
                  f"Pending items of {gp['gate_pass_no']} were written off by {user['full_name']}: {reason.strip()}", gp["id"], dedupe=f"closed_writeoff:{gp['id']}:{len(done)}:{scalar(c, 'SELECT count(*) FROM returnable_transactions WHERE returnable_item_id IN (SELECT id FROM returnable_items WHERE record_id = :r)', r=rec['id'])}")
    return return_detail(user, rec["id"])


def reverse(user, txn_id, reason: str):
    if "return.close" not in user["perms"]:
        raise Forbidden("Only Admin/Audit or the Master Admin may reverse a return posting")
    if not reason or not reason.strip():
        raise Invalid("A reason is required", "REASON_REQUIRED")
    with tx() as c:
        t = one(c, "SELECT * FROM returnable_transactions WHERE id = :t", t=txn_id)
        if not t or t["txn_type"] == "REVERSAL":
            raise NotFound("Transaction")
        ri0 = one(c, "SELECT record_id FROM returnable_items WHERE id = :i", i=t["returnable_item_id"])
        rec = one(c, "SELECT * FROM returnable_records WHERE id = :r FOR UPDATE", r=ri0["record_id"])
        ri = one(c, "SELECT * FROM returnable_items WHERE id = :i FOR UPDATE", i=t["returnable_item_id"])
        if one(c, "SELECT 1 AS x FROM returnable_transactions WHERE reverses_txn_id = :t", t=txn_id):
            raise Conflict("ALREADY_REVERSED", "This posting was already reversed")
        col = "qty_returned" if t["txn_type"] == "RETURN" else "qty_adjusted"
        q(c, f"UPDATE returnable_items SET {col} = {col} - :v, row_version = row_version + 1 WHERE id = :i", v=t["quantity"], i=ri["id"])
        q(c, "INSERT INTO returnable_transactions (returnable_item_id, txn_type, quantity, reason, reverses_txn_id, recorded_by) VALUES (:i, 'REVERSAL', :v, :r, :t, :u)",
          i=ri["id"], v=t["quantity"], r=reason.strip(), t=txn_id, u=user["id"])
        new, ogp = recompute_record(c, rec["id"], user["id"], reason=f"Reversal: {reason.strip()}")
        audit(c, "return.reverse", "gate_pass", ogp["id"], f"Posting reversed on {ogp['gate_pass_no']}", gate_pass_id=ogp["id"],
              after={"txn": str(txn_id), "type": t["txn_type"], "quantity": str(t["quantity"]), "reason": reason.strip(), "record_status": new}, severity="WARN")
    return return_detail(user, rec["id"])


# ======================= ADMIN / AUDIT VERIFICATION =======================
def verify(user, gp_id, result: str, notes: str | None):
    if "admin.verify" not in user["perms"]:
        raise Forbidden()
    if result not in ("VERIFIED", "DISCREPANCY"):
        raise Invalid("Invalid result", "VALIDATION_ERROR")
    if result == "DISCREPANCY" and not (notes or "").strip():
        raise Invalid("Notes are required when reporting a discrepancy", "REASON_REQUIRED")
    with tx() as c:
        gp = gp_svc.load(c, gp_id, lock=True)
        if not scalar(c, "SELECT count(*) FROM gate_pass_gate_events WHERE gate_pass_id = :g", g=gp["id"]):
            raise Conflict("INVALID_TRANSITION", "Only gate passes that have passed the gate can be verified")
        q(c, "INSERT INTO gate_pass_verifications (gate_pass_id, verification_type, result, notes, verified_by) VALUES (:g, 'ADMIN_AUDIT', :r, :n, :u)",
          g=gp["id"], r=result, n=(notes or "").strip() or None, u=user["id"])
        audit(c, "gatepass.verify", "gate_pass", gp["id"], f"Admin/Audit {result.lower()} for {gp['gate_pass_no']}", gate_pass_id=gp["id"], after={"result": result, "notes": notes},
              severity="WARN" if result == "DISCREPANCY" else "INFO")
    return gp_svc.get_detail(user, gp_id)


# ======================= SECURITY CONSOLE =======================
def security_queue(user, pg, kind: str, search: str | None):
    perm, tcode = ("security.gateout", "OUTWARD") if kind == "out" else ("security.gatein", "INWARD")
    if perm not in user["perms"]:
        raise Forbidden()
    from ..core.paging import envelope
    p = {"t": tcode}
    w = "t.code = :t AND g.status = 'APPROVED'"
    if search:
        w += " AND (g.gate_pass_no ILIKE :s OR g.vehicle_no_normalized LIKE :sn OR g.reference_no ILIKE :s)"
        p["s"] = f"%{search}%"
        p["sn"] = f"%{''.join(ch for ch in search.upper() if ch.isalnum())}%"
    with tx() as c:
        base = f"FROM gate_passes g JOIN gate_pass_types t ON t.id = g.type_id LEFT JOIN locations l ON l.id = g.location_id LEFT JOIN users cu ON cu.id = g.created_by WHERE {w}"
        total = scalar(c, f"SELECT count(*) {base}", **p)
        items = rows(c, f"""SELECT g.id, g.gate_pass_no, t.code AS type, g.status, g.reference_no, g.vehicle_no, g.seal_no, l.name AS location, g.approved_at, g.has_returnable,
                            cu.full_name AS created_by_name, (SELECT count(*) FROM gate_pass_items i WHERE i.gate_pass_id = g.id) AS items_count
                            {base} ORDER BY g.approved_at LIMIT :lim OFFSET :off""", lim=pg.size, off=pg.offset, **p)
        return envelope(items, total, pg)


# ======================= REMINDERS (worker) =======================
def schedule_points(offsets, repeat):
    pts = sorted(offsets)
    last = pts[-1] if pts else 0
    return pts, last, repeat


def run_reminders(today=None) -> int:
    """For open returnables, send return_due/return_overdue per schedule: on due date, +3d, +7d, then weekly. Idempotent via dedupe keys."""
    today = today or gp_svc.today_local()
    sent = 0
    with tx() as c:
        offsets = ss.get("return.reminder_offsets_days", c) or [0, 3, 7]
        repeat = ss.get("return.reminder_repeat_days", c) or 7
        recs = rows(c, """SELECT rr.id, rr.expected_return_date, rr.reminder_count, g.id AS gp_id, g.gate_pass_no, g.created_by, g.responsible_user_id
                          FROM returnable_records rr JOIN gate_passes g ON g.id = rr.source_gate_pass_id
                          WHERE rr.status IN ('OPEN','PARTIALLY_RETURNED') AND rr.expected_return_date <= :t FOR UPDATE OF rr SKIP LOCKED""", t=today)
        for r in recs:
            late = (today - r["expected_return_date"]).days
            reached = sum(1 for o in offsets if late >= o)
            if late > max(offsets):
                reached = len(offsets) + (late - max(offsets)) // repeat
            if reached <= r["reminder_count"]:
                continue
            n = reached
            ev = "return_due" if late == 0 else "return_overdue"
            to = {r["created_by"]} | ({r["responsible_user_id"]} if r["responsible_user_id"] else set()) | set(nt.holders_of(c, "return.writeoff"))
            nt.notify(c, to, ev, f"{'Return due' if late == 0 else 'Return overdue'}: {r['gate_pass_no']}",
                      f"Returnable items of {r['gate_pass_no']} are {'due today' if late == 0 else f'overdue by {late} day(s)'}.", r["gp_id"], dedupe=f"{ev}:{r['id']}:{n}")
            q(c, "UPDATE returnable_records SET reminder_count = :n, last_reminder_at = now() WHERE id = :i", n=n, i=r["id"])
            sent += 1
    return sent
