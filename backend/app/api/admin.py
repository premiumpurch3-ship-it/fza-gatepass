from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from ..core import deps
from ..core.db import tx
from ..core.paging import Page
from ..core import settings_store as ss
from ..services import admin as svc

router = APIRouter(tags=["administration"])
users_perm = deps.require("admin.users")
roles_perm = deps.require("admin.roles")
settings_perm = deps.require("admin.settings")


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._-]{3,50}$")
    full_name: str = Field(min_length=1, max_length=120)
    email: str | None = None
    employee_code: str | None = None
    password: str
    department_id: str | None = None
    phone: str | None = None
    role_codes: list[str] = []
    must_change_password: bool = True


class UserPatch(BaseModel):
    full_name: str | None = Field(None, min_length=1, max_length=120)
    email: str | None = None
    employee_code: str | None = None
    department_id: str | None = None
    phone: str | None = None


@router.get("/users")
def list_users(pg: Page = Depends(), search: str | None = None, active: bool | None = None, role: str | None = None, _=Depends(users_perm)):
    return svc.list_users(pg, search, active, role)


@router.get("/users/lookup")
def user_lookup(q: str | None = Query(None, max_length=60), _=Depends(deps.current_user)):
    return svc.user_lookup(q)


@router.post("/users", status_code=201)
def create_user(body: UserIn, user=Depends(users_perm)):
    return svc.create_user(user, body.model_dump())


@router.get("/users/{uid}")
def get_user(uid: str, _=Depends(users_perm)):
    return svc.get_user(uid)


@router.patch("/users/{uid}")
def patch_user(uid: str, body: UserPatch, user=Depends(users_perm)):
    return svc.update_user(user, uid, body.model_dump(exclude_unset=True))


@router.post("/users/{uid}/activate")
def activate(uid: str, user=Depends(users_perm)):
    return svc.set_active(user, uid, True)


@router.post("/users/{uid}/deactivate")
def deactivate(uid: str, user=Depends(users_perm)):
    return svc.set_active(user, uid, False)


@router.post("/users/{uid}/reset-password")
def reset_pw(uid: str, user=Depends(users_perm)):
    return svc.reset_password(user, uid)


@router.post("/users/{uid}/unlock")
def unlock(uid: str, user=Depends(users_perm)):
    return svc.unlock(user, uid)


@router.delete("/users/{uid}/sessions")
def force_logout(uid: str, user=Depends(users_perm)):
    svc.force_logout(user, uid)
    return {"ok": True}


class RolesIn(BaseModel):
    role_codes: list[str]


class OverrideIn(BaseModel):
    code: str
    effect: Literal["GRANT", "DENY"]


class OverridesIn(BaseModel):
    overrides: list[OverrideIn]


@router.put("/users/{uid}/roles")
def put_roles(uid: str, body: RolesIn, user=Depends(roles_perm)):
    return svc.put_roles(user, uid, body.role_codes)


@router.put("/users/{uid}/permissions")
def put_perms(uid: str, body: OverridesIn, user=Depends(roles_perm)):
    return svc.put_permission_overrides(user, uid, [o.model_dump() for o in body.overrides])


class RoleIn(BaseModel):
    code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,40}$")
    name: str
    description: str | None = None
    permissions: list[str] = []


class RolePatch(BaseModel):
    name: str | None = None
    description: str | None = None
    is_active: bool | None = None
    permissions: list[str] | None = None


@router.get("/roles")
def roles(_=Depends(roles_perm)):
    return svc.list_roles()


@router.post("/roles", status_code=201)
def create_role(body: RoleIn, user=Depends(roles_perm)):
    return svc.create_role(user, body.model_dump())


@router.patch("/roles/{rid}")
def patch_role(rid: str, body: RolePatch, user=Depends(roles_perm)):
    return svc.update_role(user, rid, body.model_dump(exclude_unset=True))


@router.get("/permissions")
def permissions(_=Depends(roles_perm)):
    return svc.list_permissions()


# -------- master data: reading is open to any signed-in user (dropdowns); writes need admin.settings --------
class MD(BaseModel):
    model_config = {"extra": "allow"}


def _md_routes(kind: str):
    @router.get(f"/{kind}", name=f"list_{kind}")
    def _list(include_inactive: bool = False, user=Depends(deps.current_user)):
        return svc.md_list(kind, include_inactive and "admin.settings" in user["perms"])

    @router.post(f"/{kind}", status_code=201, name=f"create_{kind}")
    def _create(body: MD, user=Depends(settings_perm)):
        return svc.md_create(user, kind, body.model_dump())

    @router.patch(f"/{kind}/{{rid}}", name=f"update_{kind}")
    def _update(rid: str, body: MD, user=Depends(settings_perm)):
        return svc.md_update(user, kind, rid, body.model_dump())


for _k in svc.MASTER:
    _md_routes(_k)


@router.get("/lookups")
def lookups(_=Depends(deps.current_user)):
    return svc.lookup_lists()


@router.get("/lookups/{code}/options")
def lookup_opts(code: str, include_inactive: bool = False, user=Depends(deps.current_user)):
    return svc.lookup_options(code, include_inactive and "admin.settings" in user["perms"])


class OptionIn(BaseModel):
    value: str | None = None
    label: str | None = None
    sort_order: int | None = None
    is_active: bool | None = None


@router.post("/lookups/{code}/options", status_code=201)
def add_opt(code: str, body: OptionIn, user=Depends(settings_perm)):
    return svc.lookup_option_upsert(user, code, body.model_dump(exclude_unset=True))


@router.patch("/lookups/{code}/options/{oid}")
def upd_opt(code: str, oid: str, body: OptionIn, user=Depends(settings_perm)):
    return svc.lookup_option_upsert(user, code, body.model_dump(exclude_unset=True), oid)


@router.get("/settings/public")
def public_settings():
    with tx() as c:
        return {r["key"]: r["value"] for r in ss.list_all(c, public_only=True)}


@router.get("/settings")
def all_settings(_=Depends(settings_perm)):
    with tx() as c:
        return ss.list_all(c)


class SettingIn(BaseModel):
    value: object


@router.put("/settings/{key}")
def put_setting(key: str, body: SettingIn, user=Depends(settings_perm)):
    return svc.put_setting(user, key, body.value)
