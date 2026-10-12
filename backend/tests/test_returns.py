import threading
from datetime import date, timedelta

import pytest

from tests.conftest import (approve_outward, gate_out, item, new_outward, returned_inward, submitted_approved_outward)
from app.core.db import one, q, tx


def balances(w, outward_id, line=0):
    d = w.audit.get(f"/gate-passes/{outward_id}").json()
    r = d["items"][line]["returnable"]
    return float(r["qty_out"]), float(r["qty_returned"]), float(r["qty_pending"]), r["status"], d["status"], d["return_record"]["status"]


def test_critical_return_scenario_10_4_3_3_then_reject(world):
    """The acceptance test from the build prompt: 10 out, return 4 -> 6 pending, 3 -> 3, 3 -> 0 (fully returned), then 1 more is rejected."""
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    assert balances(w, out["id"]) == (10.0, 0.0, 10.0, "PENDING", "PENDING_RETURN", "OPEN")
    assert returned_inward(w, out["id"], 4).status_code == 200
    assert balances(w, out["id"]) == (10.0, 4.0, 6.0, "PARTIAL", "PARTIALLY_RETURNED", "PARTIALLY_RETURNED")
    assert returned_inward(w, out["id"], 3).status_code == 200
    assert balances(w, out["id"]) == (10.0, 7.0, 3.0, "PARTIAL", "PARTIALLY_RETURNED", "PARTIALLY_RETURNED")
    assert returned_inward(w, out["id"], 3).status_code == 200
    assert balances(w, out["id"]) == (10.0, 10.0, 0.0, "RETURNED", "CLOSED", "COMPLETED")           # fully returned
    # nothing pending any more: the picker no longer offers it and an extra return is impossible
    lines = w.creator.get(f"/gate-passes/{out['id']}/returnable-lines")
    assert lines.status_code == 404


def test_over_return_is_rejected_at_submit_and_at_gate_in(world):
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    returned_inward(w, out["id"], 8)
    # D-04: 10 original, 8 returned, pending 2: declaring 3 is rejected when the inward is submitted
    r = returned_inward(w, out["id"], 3)
    assert r.status_code == 422
    assert any(e.get("code") == "RETURN_EXCEEDS_PENDING" for e in r.json()["details"]["errors"])
    # even if Security records 3 at Gate In (declared 2), the posting is refused and nothing changes
    lines = w.creator.get(f"/gate-passes/{out['id']}/returnable-lines").json()
    ln = lines[0]
    gp = w.creator.post("/gate-passes", {"type": "INWARD", "values": {"location_id": w.loc2, "responsible": {"name": "R"}, "inward_kind": "RETURN_AGAINST_OUTWARD"},
                                         "items": [{"source_outward_item_id": ln["source_outward_item_id"], "values": {"item_description": "Laptop", "quantity": 2, "unit_id": ln["unit_id"], "is_returnable": False}}]}).json()
    w.creator.post(f"/gate-passes/{gp['id']}/submit")
    w.inward_appr.post(f"/gate-passes/{gp['id']}/approve", {})
    item_id = w.creator.get(f"/gate-passes/{gp['id']}").json()["items"][0]["id"]
    g = w.sec.post(f"/gate-passes/{gp['id']}/gate-in", {"items": [{"id": item_id, "verified_quantity": 3}]})
    assert g.status_code == 409 and g.json()["code"] == "RETURN_EXCEEDS_PENDING"
    assert balances(w, out["id"])[1:3] == (8.0, 2.0)
    assert w.creator.get(f"/gate-passes/{gp['id']}").json()["status"] == "APPROVED"            # inward untouched, can still be processed
    assert w.sec.post(f"/gate-passes/{gp['id']}/gate-in", {}).status_code == 200


def test_database_itself_refuses_over_return(world):
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    with pytest.raises(Exception) as e:
        with tx() as c:
            q(c, "UPDATE returnable_items SET qty_returned = qty_out + 1")
    assert "ck_ri__no_overreturn" in str(e.value)


def test_concurrent_gate_ins_cannot_over_return(world):
    """Two inward passes each return 6 of 10 at the same moment: exactly one may succeed."""
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    ln = w.creator.get(f"/gate-passes/{out['id']}/returnable-lines").json()[0]
    ids = []
    for _ in range(2):          # declared 6 each is fine individually (6 <= 10 pending at submit time)
        gp = w.creator.post("/gate-passes", {"type": "INWARD", "values": {"location_id": w.loc2, "responsible": {"name": "R"}, "inward_kind": "RETURN_AGAINST_OUTWARD"},
                                             "items": [{"source_outward_item_id": ln["source_outward_item_id"], "values": {"item_description": "Laptop", "quantity": 6, "unit_id": ln["unit_id"], "is_returnable": False}}]}).json()
        assert w.creator.post(f"/gate-passes/{gp['id']}/submit").status_code == 200
        assert w.inward_appr.post(f"/gate-passes/{gp['id']}/approve", {}).status_code == 200
        ids.append(gp["id"])
    results = []
    barrier = threading.Barrier(2)

    def go(i):
        barrier.wait()
        results.append(w.sec.post(f"/gate-passes/{ids[i]}/gate-in", {}).status_code)

    ts = [threading.Thread(target=go, args=(i,)) for i in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(results) == [200, 409]
    assert balances(w, out["id"])[1:3] == (6.0, 4.0)


def test_writeoff_requires_permission_reason_and_is_audited(world):
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    returned_inward(w, out["id"], 8)
    # only Admin/Audit and Master Admin (D-05)
    for u in (w.creator, w.sec, w.a1, w.reporter):
        assert u.post(f"/gate-passes/{out['id']}/writeoff", {"reason": "lost"}).status_code in (403, 404)
    assert w.audit.post(f"/gate-passes/{out['id']}/writeoff", {"reason": ""}).status_code == 422
    r = w.audit.post(f"/gate-passes/{out['id']}/writeoff", {"reason": "Lost in transit, confirmed by driver"})
    assert r.status_code == 200 and r.json()["status"] == "CLOSED_ADJUSTED"
    assert balances(w, out["id"]) == (10.0, 8.0, 0.0, "ADJUSTED", "CLOSED", "CLOSED_ADJUSTED")
    log = w.master.get("/audit-logs", params={"action": "return.adjust"}).json()
    assert log["total"] == 1 and "Lost in transit" in str(log["items"][0]["after"]) and log["items"][0]["actor_username"] == w.audit.username
    # nothing left to write off
    assert w.audit.post(f"/gate-passes/{out['id']}/writeoff", {"reason": "again"}).status_code == 409


def test_reversal_reopens_a_closed_return(world):
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    returned_inward(w, out["id"], 10)
    rec = w.audit.get("/returns").json()["items"][0]
    detail = w.audit.get(f"/returns/{rec['record_id']}").json()
    txn = detail["items"][0]["history"][0]
    assert txn["txn_type"] == "RETURN"
    assert w.creator.post(f"/returns/transactions/{txn['id']}/reverse", {"reason": "x"}).status_code in (403, 404)
    r = w.audit.post(f"/returns/transactions/{txn['id']}/reverse", {"reason": "Wrong item received"})
    assert r.status_code == 200
    assert balances(w, out["id"]) == (10.0, 0.0, 10.0, "PENDING", "PENDING_RETURN", "OPEN")
    assert w.audit.post(f"/returns/transactions/{txn['id']}/reverse", {"reason": "again"}).status_code == 409


def test_overdue_status_and_reminder_schedule(world):
    w = world
    out = submitted_approved_outward(w)
    gate_out(w, out["id"])
    rec = w.audit.get("/returns").json()["items"][0]
    assert rec["overdue"] is False
    with tx() as c:       # move the due date into the past (test fixture manipulation only)
        q(c, "UPDATE returnable_records SET expected_return_date = :d", d=date.today() - timedelta(days=5))
    assert w.audit.get("/returns", params={"overdue": True}).json()["total"] == 1
    assert w.audit.get("/gate-passes", params={"overdue": True}).json()["total"] == 1
    dash = w.audit.get("/dashboard/summary").json()
    assert dash["overdue_returnables"] == 1 and dash["outstanding_returnables"] == 1
    from app.services import workflow
    today = date.today()
    # due date was today-5: points reached are +0 and +3 -> reminders 1 and 2 (the +7 point is not reached yet)
    assert workflow.run_reminders(today) == 1
    assert workflow.run_reminders(today) == 0                                    # idempotent
    with tx() as c:
        n = one(c, "SELECT count(*) AS n FROM notifications WHERE event_type IN ('return_due','return_overdue') AND channel = 'IN_APP'")["n"]
    assert n >= 1
    assert workflow.run_reminders(today + timedelta(days=3)) == 1                 # +8 days late -> the +7 point
    assert workflow.run_reminders(today + timedelta(days=10)) == 1                # +15 days late -> first weekly repeat (+14)
    assert workflow.run_reminders(today + timedelta(days=11)) == 0


def test_multiple_lines_and_partial_by_line(world):
    w = world
    out = submitted_approved_outward(w, items=[item(w, "Laptop", 10), item(w, "Printer", 1)])
    gate_out(w, out["id"])
    returned_inward(w, out["id"], 1, line=1)                                       # printer returned in full
    d = w.audit.get(f"/gate-passes/{out['id']}").json()
    assert [i["returnable"]["status"] for i in d["items"]] == ["PENDING", "RETURNED"]
    assert d["status"] == "PARTIALLY_RETURNED"
