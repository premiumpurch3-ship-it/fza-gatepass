from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..core import deps
from ..core.db import rows, scalar, tx
from ..core.errors import Forbidden, NotFound
from ..core.idem import IdempotentRoute
from ..core.paging import Page
from ..services import attachments as att, gatepass as svc, pdf, workflow as wf

router = APIRouter(prefix="/gate-passes", tags=["gate-passes"], route_class=IdempotentRoute)
U = Depends(deps.current_user)


class ItemIn(BaseModel):
    id: str | None = None
    values: dict = {}
    source_outward_item_id: str | None = None


class CreateIn(BaseModel):
    type: str
    values: dict = {}
    items: list[ItemIn] = []
    client_request_id: str | None = None


class UpdateIn(BaseModel):
    row_version: int
    values: dict = {}
    items: list[ItemIn] | None = None


@router.post("", status_code=201)
def create(body: CreateIn, user=Depends(deps.require("gatepass.create"))):
    return svc.create(user, body.type, body.values, [i.model_dump() for i in body.items], body.client_request_id)


@router.get("")
def search(pg: Page = Depends(), user=U, q: str | None = Query(None, max_length=100), type: str | None = None, status: Annotated[list[str] | None, Query()] = None,
           returnable: bool | None = None, return_status: str | None = None, overdue: bool | None = None, location_id: str | None = None,
           department_id: str | None = None, created_by: str | None = None, responsible_user_id: str | None = None, date_from: date | None = None,
           date_to: date | None = None, mine: bool | None = None, drafts: bool | None = None, pending_my_approval: bool | None = None,
           sort: str | None = None, order: str | None = None):
    return svc.search(user, pg, dict(q=q, type=type, status=status, returnable=returnable, return_status=return_status, overdue=overdue, location_id=location_id,
                                     department_id=department_id, created_by=created_by, responsible_user_id=responsible_user_id, date_from=date_from, date_to=date_to,
                                     mine=mine, drafts=drafts, pending_my_approval=pending_my_approval, sort=sort, order=order))


@router.get("/outward-search")
def outward_search(q: str | None = Query(None, max_length=100), user=Depends(deps.require("gatepass.create"))):
    """Inward picker: outward passes that still have pending returnable quantity."""
    with tx() as c:
        return rows(c, """SELECT g.id, g.gate_pass_no, l.name AS location, g.reference_no, rr.expected_return_date, rr.status,
                          (SELECT coalesce(sum(qty_pending),0) FROM returnable_items WHERE record_id = rr.id) AS qty_pending
                          FROM returnable_records rr JOIN gate_passes g ON g.id = rr.source_gate_pass_id LEFT JOIN locations l ON l.id = g.location_id
                          WHERE rr.status IN ('OPEN','PARTIALLY_RETURNED') AND (CAST(:q AS text) IS NULL OR g.gate_pass_no ILIKE :p OR g.reference_no ILIKE :p OR l.name ILIKE :p
                            OR g.vehicle_no_normalized LIKE :n OR EXISTS (SELECT 1 FROM gate_pass_items i WHERE i.gate_pass_id = g.id AND i.description ILIKE :p))
                          ORDER BY rr.expected_return_date LIMIT 30""", q=q, p=f"%{q or ''}%", n=f"%{''.join(ch for ch in (q or '').upper() if ch.isalnum())}%")


@router.get("/{gp_id}/returnable-lines")
def returnable_lines(gp_id: str, user=Depends(deps.require("gatepass.create"))):
    with tx() as c:
        data = rows(c, """SELECT i.id AS source_outward_item_id, ri.id AS returnable_item_id, i.line_no, i.description, i.item_code, u.id AS unit_id, u.code AS unit_code,
                          ri.qty_out, ri.qty_returned, ri.qty_adjusted, ri.qty_pending, ri.status
                          FROM returnable_records rr JOIN returnable_items ri ON ri.record_id = rr.id JOIN gate_pass_items i ON i.id = ri.source_item_id
                          JOIN units_of_measure u ON u.id = ri.unit_id WHERE rr.source_gate_pass_id = CAST(:g AS uuid) AND rr.status IN ('OPEN','PARTIALLY_RETURNED') ORDER BY i.line_no""", g=gp_id)
        if not data:
            raise NotFound("Open returnable gate pass")
        return data


@router.get("/{gp_id}")
def detail(gp_id: str, user=U):
    return svc.get_detail(user, gp_id)


@router.patch("/{gp_id}")
def update(gp_id: str, body: UpdateIn, user=Depends(deps.require("gatepass.edit"))):
    return svc.update(user, gp_id, body.row_version, body.values, None if body.items is None else [i.model_dump() for i in body.items])


class SubmitIn(BaseModel):
    row_version: int | None = None


@router.post("/{gp_id}/submit")
def submit(gp_id: str, body: SubmitIn | None = None, user=Depends(deps.require("gatepass.submit"))):
    return svc.submit(user, gp_id, body.row_version if body else None)


@router.post("/{gp_id}/recall")
def recall(gp_id: str, user=U):
    return svc.recall(user, gp_id)


class ReasonIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


@router.post("/{gp_id}/cancel")
def cancel(gp_id: str, body: ReasonIn, user=U):
    return svc.cancel(user, gp_id, body.reason)


@router.post("/{gp_id}/move-to-latest-form")
def latest(gp_id: str, user=U):
    return svc.move_to_latest_form(user, gp_id)


@router.get("/{gp_id}/timeline")
def timeline(gp_id: str, user=U):
    return svc.timeline(user, gp_id)


@router.get("/{gp_id}/pdf")
def pdf_(gp_id: str, user=U):
    data, name = pdf.gate_pass_pdf(user, gp_id)
    return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="{name}"'})


# ---- workflow actions ----
class DecisionIn(BaseModel):
    comments: str | None = Field(None, max_length=1000)
    level: int | None = None


@router.post("/{gp_id}/approve")
def approve(gp_id: str, body: DecisionIn | None = None, user=U):
    return wf.approve(user, gp_id, body.comments if body else None, body.level if body else None)


class RejectIn(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)
    level: int | None = None


@router.post("/{gp_id}/reject")
def reject(gp_id: str, body: RejectIn, user=U):
    return wf.reject(user, gp_id, body.reason, body.level)


class VerifiedItem(BaseModel):
    id: str
    verified_quantity: float | str | None = None
    condition_value: str | None = None


class GateIn(BaseModel):
    gate_id: str | None = None
    items: list[VerifiedItem] = []
    vehicle_no_verified: str | None = Field(None, max_length=30)
    seal_no_verified: str | None = Field(None, max_length=30)
    seal_intact: bool | None = None
    driver_name: str | None = Field(None, max_length=120)
    remarks: str | None = Field(None, max_length=500)


@router.post("/{gp_id}/gate-out")
def gate_out(gp_id: str, body: GateIn, user=U):
    return wf.gate_out(user, gp_id, body.model_dump())


@router.post("/{gp_id}/gate-in")
def gate_in(gp_id: str, body: GateIn, user=U):
    return wf.gate_in(user, gp_id, body.model_dump())


class VerifyIn(BaseModel):
    result: str
    notes: str | None = Field(None, max_length=1000)


@router.post("/{gp_id}/verify")
def verify(gp_id: str, body: VerifyIn, user=U):
    return wf.verify(user, gp_id, body.result, body.notes)


class WriteoffLine(BaseModel):
    returnable_item_id: str
    quantity: float | str


class WriteoffIn(BaseModel):
    reason: str = Field(min_length=1, max_length=500)
    lines: list[WriteoffLine] | None = None


@router.post("/{gp_id}/writeoff")
def writeoff(gp_id: str, body: WriteoffIn, user=U):
    return wf.writeoff(user, gp_id, body.reason, [l.model_dump() for l in body.lines] if body.lines else None)


# ---- attachments of a pass ----
@router.get("/{gp_id}/attachments")
def list_att(gp_id: str, user=U):
    return att.list_for_pass(user, gp_id)


class RegisterIn(BaseModel):
    filename: str = Field(min_length=1, max_length=200)
    size: int = Field(gt=0)
    content_type: str | None = None
    stage: str = "CREATION"
    item_id: str | None = None
    captured: bool = False
    capture_meta: dict = {}


@router.post("/{gp_id}/attachments", status_code=201)
def register_att(gp_id: str, body: RegisterIn, user=U):
    return att.register(user, gp_id, body.model_dump())
