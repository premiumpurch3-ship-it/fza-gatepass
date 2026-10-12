from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..core import deps
from ..services import forms as svc

router = APIRouter(tags=["forms"])
cfg = deps.require("admin.forms")


@router.get("/forms")
def list_forms(_=Depends(cfg)):
    return svc.list_forms()


@router.get("/forms/{code}/published")
def published(code: str, _=Depends(deps.current_user)):
    return svc.published(code)


@router.get("/form-versions/{vid}")
def version(vid: str, _=Depends(deps.current_user)):
    return svc.get_version(vid)


@router.get("/forms/{code}/versions")
def versions(code: str, _=Depends(cfg)):
    return svc.versions(code)


class DraftIn(BaseModel):
    from_version_id: str | None = None


@router.post("/forms/{code}/draft", status_code=201)
def create_draft(code: str, body: DraftIn | None = None, user=Depends(cfg)):
    return svc.create_draft(user, code, body.from_version_id if body else None)


@router.get("/forms/{code}/draft")
def get_draft(code: str, _=Depends(cfg)):
    return svc.get_draft(code)


@router.delete("/forms/{code}/draft")
def discard(code: str, user=Depends(cfg)):
    svc.discard_draft(user, code)
    return {"ok": True}


class OptionIn(BaseModel):
    value: str
    label: str
    active: bool = True
    default: bool = False


class FieldIn(BaseModel):
    key: str
    label: str = Field(min_length=1, max_length=80)
    type: str
    scope: str = "HEADER"
    section: str | None = None
    required: bool = False
    placeholder: str | None = None
    help: str | None = None
    default: object | None = None
    validation: dict = {}
    src: str = "NONE"
    lookup: str | None = None
    options: list[OptionIn] = []
    show_list: bool = False
    show_pdf: bool = True
    searchable: bool = False
    ui: dict = {}
    rule: dict | None = None
    applies_to: list[str] = ["OUTWARD", "INWARD"]


@router.post("/forms/draft/fields", status_code=201)
def add_field(body: FieldIn, user=Depends(cfg)):
    spec = body.model_dump()
    spec["list"], spec["pdf"], spec["search"] = spec.pop("show_list"), spec.pop("show_pdf"), spec.pop("searchable")
    if spec["type"] in ("DROPDOWN", "MULTISELECT") and spec["src"] == "NONE":
        spec["src"] = "LOOKUP" if spec.get("lookup") else "INLINE"
    return svc.add_field(user, spec, [a.upper() for a in body.applies_to])


class FieldPatch(BaseModel):
    model_config = {"extra": "forbid"}
    label: str | None = None
    type: str | None = None
    is_required: bool | None = None
    is_active: bool | None = None
    display_order: int | None = None
    default_value: object | None = None
    placeholder: str | None = None
    help_text: str | None = None
    validation: dict | None = None
    show_in_list: bool | None = None
    show_in_pdf: bool | None = None
    is_searchable: bool | None = None
    ui: dict | None = None
    visibility_rule: dict | None = None
    section: str | None = None
    options_source: str | None = None
    lookup: str | None = None


@router.patch("/forms/{code}/draft/fields/{key}")
def patch_field(code: str, key: str, body: FieldPatch, user=Depends(cfg)):
    return svc.patch_field(user, code, key, body.model_dump(exclude_unset=True))


@router.delete("/forms/{code}/draft/fields/{key}")
def delete_field(code: str, key: str, user=Depends(cfg)):
    svc.delete_field(user, code, key)
    return {"ok": True}


class OptionsIn(BaseModel):
    options: list[OptionIn]


@router.put("/forms/{code}/draft/fields/{key}/options")
def set_options(code: str, key: str, body: OptionsIn, user=Depends(cfg)):
    svc.set_options(user, code, key, [o.model_dump() for o in body.options])
    return {"ok": True}


class OrderIn(BaseModel):
    order: list[str]


@router.put("/forms/{code}/draft/order")
def reorder(code: str, body: OrderIn, user=Depends(cfg)):
    svc.reorder(user, code, body.order)
    return {"ok": True}


@router.post("/forms/{code}/draft/validate")
def validate(code: str, _=Depends(cfg)):
    return svc.validate_draft(code)


@router.get("/forms/{code}/draft/diff")
def diff(code: str, _=Depends(cfg)):
    return svc.diff_draft(code)


class PublishIn(BaseModel):
    change_note: str
    also: list[str] = []


@router.post("/forms/{code}/draft/publish")
def publish(code: str, body: PublishIn, user=Depends(cfg)):
    return svc.publish(user, [code] + [a for a in body.also if a.upper() != code.upper()], body.change_note)
