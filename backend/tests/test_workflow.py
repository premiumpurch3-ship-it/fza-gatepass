import re
from datetime import date, timedelta

from tests.conftest import (approve_outward, gate_out, header, item, jpeg_bytes, new_outward, returned_inward, submitted_approved_outward, upload)


def test_outward_creation_validation_and_number_only_on_submit(world):
    w = world
    gp = new_outward(w, with_photo=False)
    assert gp["status"] == "DRAFT" and gp["gate_pass_no"] is None          # D-01: drafts do not consume numbers
    r = w.creator.post(f"/gate-passes/{gp['id']}/submit")
    assert r.status_code == 422                                              # D-14: at least one photo required
    assert any("photo" in e["message"].lower() for e in r.json()["details"]["errors"])
    upload(w.creator, gp["id"], jpeg_bytes())
    r = w.creator.post(f"/gate-passes/{gp['id']}/submit")
    assert r.status_code == 200
    d = r.json()
    year = date.today().year
    assert re.fullmatch(rf"GP-{year}-000001", d["gate_pass_no"]) and d["status"] == "PENDING_L1"
    # abandoned drafts did not burn numbers: second pass gets 000002
    gp2 = new_outward(w)
    assert w.creator.post(f"/gate-passes/{gp2['id']}/submit").json()["gate_pass_no"].endswith("000002")


def test_required_fields_and_returnable_due_date(world):
    w = world
    r = w.creator.post("/gate-passes", {"type": "OUTWARD", "values": {"remarks": "x"}, "items": []})
    assert r.status_code == 201
    gp = r.json()
    r = w.creator.post(f"/gate-passes/{gp['id']}/submit")
    assert r.status_code == 422
    fields = {e.get("field") for e in r.json()["details"]["errors"]}
    assert {"location_id", "responsible", "items", "photos"} <= fields
    gp = new_outward(w, expected_return_date=None)
    r = w.creator.post(f"/gate-passes/{gp['id']}/submit")
    assert r.status_code == 422 and any(e.get("field") == "expected_return_date" for e in r.json()["details"]["errors"])   # D-06
    gp = new_outward(w, expected_return_date=(date.today() - timedelta(days=1)).isoformat())
    assert w.creator.post(f"/gate-passes/{gp['id']}/submit").status_code == 422


def test_two_level_outward_approval_rules(world):
    w = world
    gp = new_outward(w)
    w.creator.post(f"/gate-passes/{gp['id']}/submit")
    # Level 2 cannot act first
    assert w.a2.post(f"/gate-passes/{gp['id']}/approve", {}).status_code == 403
    # approver without permission
    assert w.sec.post(f"/gate-passes/{gp['id']}/approve", {}).status_code in (403, 404)
    r = w.a1.post(f"/gate-passes/{gp['id']}/approve", {"comments": "fine"})
    assert r.status_code == 200 and r.json()["status"] == "PENDING_L2"
    # level 1 user cannot also do level 2 (no permission), L1 can't approve twice
    assert w.a1.post(f"/gate-passes/{gp['id']}/approve", {}).status_code == 403
    r = w.a2.post(f"/gate-passes/{gp['id']}/approve", {})
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    d = r.json()
    assert [(a["level"], a["decision"]) for a in d["approvals"]] == [(1, "APPROVED"), (2, "APPROVED")]
    assert all(a["approver_name"] and a["decided_at"] and a["platform"] == "android" and a["user_agent"] for a in d["approvals"])


def test_self_approval_is_forbidden_even_for_master_admin(world, make_user):
    w = world
    both = make_user(["gatepass_creator", "approver_l1", "approver_l2"])
    gp = new_outward(type("X", (), {**w.__dict__, "creator": both}) if False else w)       # created by w.creator
    # a user holding creator + approval roles creates and tries to approve own pass
    r = both.post("/gate-passes", {"type": "OUTWARD", "values": header(w), "items": [item(w)]}).json()
    upload(both, r["id"], jpeg_bytes())
    both.post(f"/gate-passes/{r['id']}/submit")
    resp = both.post(f"/gate-passes/{r['id']}/approve", {})
    assert resp.status_code == 403 and resp.json()["code"] == "SELF_APPROVAL_FORBIDDEN"        # D-07 server side
    # master admin who created a pass cannot approve it either (D-08: no hidden bypass)
    m = w.master
    rm = m.post("/gate-passes", {"type": "OUTWARD", "values": header(w), "items": [item(w)]}).json()
    upload(m, rm["id"], jpeg_bytes())
    m.post(f"/gate-passes/{rm['id']}/submit")
    assert m.post(f"/gate-passes/{rm['id']}/approve", {}).json()["code"] == "SELF_APPROVAL_FORBIDDEN"
    # but the master admin may approve someone else's pass, flagged in the audit trail
    g2 = new_outward(w)
    w.creator.post(f"/gate-passes/{g2['id']}/submit")
    r = m.post(f"/gate-passes/{g2['id']}/approve", {})
    assert r.status_code == 200 and r.json()["approvals"][0]["approver_was_master_admin"] is True


def test_rejection_resubmission_keeps_history(world):
    w = world
    gp = new_outward(w)
    w.creator.post(f"/gate-passes/{gp['id']}/submit")
    assert w.a1.post(f"/gate-passes/{gp['id']}/reject", {"reason": ""}).status_code == 422
    r = w.a1.post(f"/gate-passes/{gp['id']}/reject", {"reason": "Quantity unclear"})
    assert r.status_code == 200 and r.json()["status"] == "REJECTED" and r.json()["last_rejection_reason"] == "Quantity unclear"
    # rejected pass is editable and can be resubmitted: new round, approvals restart
    d = w.creator.get(f"/gate-passes/{gp['id']}").json()
    r = w.creator.patch(f"/gate-passes/{gp['id']}", {"row_version": d["row_version"], "values": {"remarks": "fixed"}})
    assert r.status_code == 200
    r = w.creator.post(f"/gate-passes/{gp['id']}/submit")
    assert r.status_code == 200 and r.json()["round_no"] == 2 and r.json()["revision_no"] == 2 and r.json()["status"] == "PENDING_L1"
    assert len(r.json()["approvals"]) == 1 and r.json()["approvals"][0]["decision"] == "REJECTED"
    approve_outward(w, gp["id"])


def test_approved_pass_cannot_be_edited_but_can_be_cancelled(world):
    w = world
    d = submitted_approved_outward(w)
    r = w.creator.patch(f"/gate-passes/{d['id']}", {"row_version": d["row_version"], "values": {"remarks": "new"}})
    assert r.status_code == 409 and r.json()["code"] == "NOT_EDITABLE"                         # D-19
    assert w.creator.post(f"/gate-passes/{d['id']}/cancel", {"reason": ""}).status_code == 422
    r = w.creator.post(f"/gate-passes/{d['id']}/cancel", {"reason": "Wrong quantity, recreate"})
    assert r.status_code == 200 and r.json()["status"] == "CANCELLED"


def test_stale_edit_is_rejected(world):
    w = world
    gp = new_outward(w)
    r = w.creator.patch(f"/gate-passes/{gp['id']}", {"row_version": gp["row_version"], "values": {"remarks": "a"}})
    assert r.status_code == 200
    r = w.creator.patch(f"/gate-passes/{gp['id']}", {"row_version": gp["row_version"], "values": {"remarks": "b"}})
    assert r.status_code == 409 and r.json()["code"] == "STALE_VERSION"


def test_gate_out_requires_approval_and_stamps_actual_time(world):
    w = world
    gp = new_outward(w)
    w.creator.post(f"/gate-passes/{gp['id']}/submit")
    r = w.sec.post(f"/gate-passes/{gp['id']}/gate-out", {})
    assert r.status_code in (409, 404)                                                           # not approved yet
    approve_outward(w, gp["id"])
    assert w.creator.post(f"/gate-passes/{gp['id']}/gate-out", {}).status_code == 403            # not security
    d = gate_out(w, gp["id"], remarks="checked", vehicle_no_verified="abc 123")
    ev = d["gate_events"][0]
    assert d["status"] == "PENDING_RETURN" and ev["event_type"] == "GATE_OUT" and ev["occurred_at"] and ev["recorded_by_name"]
    assert ev["has_discrepancy"] is False
    assert d["return_record"]["status"] == "OPEN"
    assert w.sec.post(f"/gate-passes/{gp['id']}/gate-out", {}).status_code == 409                # cannot gate out twice


def test_gate_out_cannot_exceed_approved_quantity_and_flags_discrepancy(world):
    w = world
    d = submitted_approved_outward(w)
    it = d["items"][0]
    assert w.sec.post(f"/gate-passes/{d['id']}/gate-out", {"items": [{"id": it["id"], "verified_quantity": 11}]}).status_code == 422
    out = gate_out(w, d["id"], items=[{"id": it["id"], "verified_quantity": 9}])
    assert out["gate_events"][0]["has_discrepancy"] is True
    assert float(out["items"][0]["returnable"]["qty_out"]) == 9.0


def test_non_returnable_outward_completes_after_gate_out(world):
    w = world
    d = submitted_approved_outward(w, items=[item(w, "Sample box", 2, returnable=False)], expected_return_date=None)
    out = gate_out(w, d["id"])
    assert out["status"] == "CLOSED" and out["return_record"] is None


def test_inward_requires_single_approval_and_links_to_outward(world):
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    inward = returned_inward(w, out["id"], 4, submit=True, approve=False, gate=False).json()
    assert inward["status"] == "PENDING_L1" and inward["required_approval_levels"] == 1          # D-02
    assert w.a1.post(f"/gate-passes/{inward['id']}/approve", {}).status_code in (403, 404)       # outward approver has no inward right
    r = w.inward_appr.post(f"/gate-passes/{inward['id']}/approve", {})
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    assert r.json()["links"]["returns_against"][0]["gate_pass_no"] == out["gate_pass_no"]
    # security cannot gate in before approval of a different pass; and gate-in works now
    g = w.sec.post(f"/gate-passes/{inward['id']}/gate-in", {})
    assert g.status_code == 200 and g.json()["status"] == "CLOSED" and g.json()["gate_events"][0]["event_type"] == "GATE_IN"


def test_search_filters_and_visibility(world):
    w = world
    d = submitted_approved_outward(w, vehicle_no="KHI-7788", reference_no="PO-555")
    r = w.audit.get("/gate-passes", params={"q": "khi7788"}).json()
    assert r["total"] == 1 and r["items"][0]["gate_pass_no"] == d["gate_pass_no"]
    assert w.audit.get("/gate-passes", params={"q": "PO-555", "type": "OUTWARD", "status": "APPROVED"}).json()["total"] == 1
    assert w.audit.get("/gate-passes", params={"q": "Laptop"}).json()["total"] == 1               # item search
    assert w.audit.get("/gate-passes", params={"status": "CLOSED"}).json()["total"] == 0
    # another creator cannot see or fetch it (404, not 403)
    assert w.creator2.get(f"/gate-passes/{d['id']}").status_code == 404
    assert w.creator2.get("/gate-passes").json()["total"] == 0
    # approver sees pending queue, not drafts of others
    assert w.a1.get("/approvals/pending").json()["total"] == 0


def test_idempotent_submit_and_create(world):
    w = world
    gp = new_outward(w)
    k = "key-submit-1"
    r1 = w.creator.post(f"/gate-passes/{gp['id']}/submit", key=k)
    r2 = w.creator.post(f"/gate-passes/{gp['id']}/submit", key=k)
    assert r1.status_code == 200 and r2.status_code == 200 and r2.headers.get("Idempotent-Replay") == "true"
    assert r1.json()["gate_pass_no"] == r2.json()["gate_pass_no"]
    # client_request_id de-duplicates creates (offline retry)
    body = {"type": "OUTWARD", "values": header(w), "items": [item(w)], "client_request_id": "7d444840-9dc0-11d1-b245-5ffdce74fad2"}
    a, b = w.creator.post("/gate-passes", body).json(), w.creator.post("/gate-passes", body).json()
    assert a["id"] == b["id"]


def test_pickers_work_without_a_search_term(world):
    """Regression (found by the browser E2E): the inward picker and user lookup must work with no query text."""
    w = world
    out = submitted_approved_outward(w)
    assert w.creator.get("/gate-passes/outward-search").json() == []                  # not gated out yet -> nothing open
    gate_out(w, out["id"])
    r = w.creator.get("/gate-passes/outward-search").json()
    assert len(r) == 1 and r[0]["gate_pass_no"] == out["gate_pass_no"] and float(r[0]["qty_pending"]) == 10.0
    assert w.creator.get("/gate-passes/outward-search", params={"q": "laptop"}).json()[0]["id"] == out["id"]
    assert len(w.creator.get("/users/lookup").json()) >= 5
