import secrets
import string

from ..core import rbac, settings_store as ss
from ..core.audit import audit, diff
from ..core.db import J, one, q, rows, scalar, tx
from ..core.errors import AppError, Conflict, Forbidden, Invalid, NotFound
from ..core.paging import Page, envelope
from ..core.security import check_password_policy, hash_password


def temp_password() -> str:
    al = string.ascii_letters + string.digits
    while True:
        p = "".join(secrets.choice(al) for _ in range(14))
        if any(ch.isdigit() for ch in p) and any(ch.isalpha() for ch in p):
            return p


USER_COLS = "id, username, full_name, email, employee_code, is_active, is_master_admin, department_id, phone, mfa_enabled, must_change_password, last_login_at, created_at"


def _user_detail(c, uid):
    u = one(c, f"SELECT {USER_COLS}, locked_until FROM users WHERE id = :u", u=uid)
    if not u:
        raise NotFound("User")
    u["roles"] = [r["code"] for r in rows(c, "SELECT r.code FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = :u ORDER BY r.code", u=uid)]
    u["permission_overrides"] = rows(c, "SELECT permission_code AS code, effect FROM user_permissions WHERE user_id = :u ORDER BY 1", u=uid)
    u["effective_permissions"] = sorted(rbac.effective_permissions(c, {**u, "authz_version": scalar(c, "SELECT authz_version FROM users WHERE id=:u", u=uid)}))
    return u


def create_user(actor, d: dict) -> dict:
    with tx() as c:
        check_password_policy(d["password"], ss.get("security.password_min_length", c), d["username"])
        username = d["username"].strip().lower()
        if one(c, "SELECT 1 AS x FROM users WHERE username = :u", u=username):
            raise Conflict("DUPLICATE", "Username already exists")
        u = one(c, """INSERT INTO users (username, full_name, email, employee_code, password_hash, department_id, phone, created_by, must_change_password)
                      VALUES (:un, :fn, :em, :ec, :ph, :dp, :ph2, :cb, :mc) RETURNING id""",
                un=username, fn=d["full_name"], em=d.get("email"), ec=d.get("employee_code"), ph=hash_password(d["password"]),
                dp=d.get("department_id"), ph2=d.get("phone"), cb=actor["id"], mc=d.get("must_change_password", True))
        _set_roles(c, actor, u["id"], d.get("role_codes") or [])
        audit(c, "user.create", "user", u["id"], f"User '{username}' created", after={"username": username, "roles": d.get("role_codes") or []})
        return _user_detail(c, u["id"])


def _set_roles(c, actor, uid, codes):
    found = {r["code"]: r["id"] for r in rows(c, "SELECT id, code FROM roles WHERE code = ANY(:c) AND is_active", c=list(codes))}
    missing = set(codes) - {k.lower() for k in found} - set(found)
    if missing:
        raise Invalid(f"Unknown roles: {sorted(missing)}", "UNKNOWN_ROLE")
    q(c, "DELETE FROM user_roles WHERE user_id = :u", u=uid)
    for rid in found.values():
        q(c, "INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (:u, :r, :a)", u=uid, r=rid, a=actor["id"])
    rbac.bump_user(c, uid)


def list_users(pg: Page, search=None, active=None, role=None):
    with tx() as c:
        where, p = ["TRUE"], {}
        if search:
            where.append("(u.username ILIKE :s OR u.full_name ILIKE :s OR u.employee_code ILIKE :s)"); p["s"] = f"%{search}%"
        if active is not None:
            where.append("u.is_active = :a"); p["a"] = active
        if role:
            where.append("EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id AND r.code = :role)"); p["role"] = role
        w = " AND ".join(where)
        total = scalar(c, f"SELECT count(*) FROM users u WHERE {w}", **p)
        items = rows(c, f"""SELECT u.id, u.username, u.full_name, u.email, u.is_active, u.is_master_admin, u.mfa_enabled, u.last_login_at,
                            (SELECT coalesce(array_agg(r.code ORDER BY r.code), '{{}}') FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id) AS roles
                            FROM users u WHERE {w} ORDER BY u.full_name LIMIT :l OFFSET :o""", l=pg.size, o=pg.offset, **p)
        return envelope(items, total, pg)


def get_user(uid):
    with tx() as c:
        return _user_detail(c, uid)


def update_user(actor, uid, d: dict):
    with tx() as c:
        u = one(c, "SELECT * FROM users WHERE id = :u FOR UPDATE", u=uid)
        if not u:
            raise NotFound("User")
        if u["is_master_admin"] and not actor["is_master_admin"]:
            raise Forbidden("Only the Master Admin can modify the Master Admin account")
        allowed = {k: d[k] for k in ("full_name", "email", "employee_code", "department_id", "phone") if k in d}
        if allowed:
            sets = ", ".join(f"{k} = :{k}" for k in allowed)
            q(c, f"UPDATE users SET {sets} WHERE id = :id", id=uid, **allowed)
            b, a = diff(u, allowed, list(allowed))
            audit(c, "user.update", "user", uid, f"User '{u['username']}' updated", before=b, after=a)
        return _user_detail(c, uid)


def set_active(actor, uid, active: bool):
    with tx() as c:
        u = one(c, "SELECT username, is_master_admin, is_active FROM users WHERE id = :u FOR UPDATE", u=uid)
        if not u:
            raise NotFound("User")
        if u["is_master_admin"]:
            raise Forbidden("The Master Admin cannot be deactivated")
        q(c, "UPDATE users SET is_active = :a, deactivated_at = CASE WHEN :a THEN NULL ELSE now() END, deactivated_by = CASE WHEN :a THEN NULL ELSE CAST(:by AS uuid) END WHERE id = :u",
          a=active, by=actor["id"], u=uid)
        rbac.bump_user(c, uid)
        if not active:
            q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'deactivated' WHERE user_id = :u AND revoked_at IS NULL", u=uid)
        audit(c, "user.activate" if active else "user.deactivate", "user", uid, f"User '{u['username']}' {'activated' if active else 'deactivated'}",
              before={"is_active": u["is_active"]}, after={"is_active": active}, severity="SECURITY")
        return _user_detail(c, uid)


def reset_password(actor, uid):
    with tx() as c:
        u = one(c, "SELECT username, password_hash, is_master_admin FROM users WHERE id = :u FOR UPDATE", u=uid)
        if not u:
            raise NotFound("User")
        if u["is_master_admin"] and not actor["is_master_admin"]:
            raise Forbidden("Only the Master Admin can reset the Master Admin password")
        pw = temp_password()
        q(c, "INSERT INTO user_password_history (user_id, password_hash) VALUES (:u, :h)", u=uid, h=u["password_hash"])
        q(c, "UPDATE users SET password_hash = :h, must_change_password = true, password_changed_at = now(), failed_login_count = 0, locked_until = NULL WHERE id = :u",
          h=hash_password(pw), u=uid)
        q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'password_reset' WHERE user_id = :u AND revoked_at IS NULL", u=uid)
        audit(c, "user.password_reset", "user", uid, f"Password reset for '{u['username']}'", severity="SECURITY")
        return {"temporary_password": pw, "must_change_password": True}


def unlock(actor, uid):
    with tx() as c:
        q(c, "UPDATE users SET locked_until = NULL, failed_login_count = 0 WHERE id = :u", u=uid)
        audit(c, "user.unlock", "user", uid, "Account unlocked", severity="SECURITY")
    return get_user(uid)


def force_logout(actor, uid):
    with tx() as c:
        q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'admin_force_logout' WHERE user_id = :u AND revoked_at IS NULL", u=uid)
        audit(c, "auth.session.revoke", "user", uid, "All sessions revoked by admin", severity="SECURITY")


def put_roles(actor, uid, codes):
    with tx() as c:
        u = one(c, "SELECT username, is_master_admin FROM users WHERE id = :u FOR UPDATE", u=uid)
        if not u:
            raise NotFound("User")
        if u["is_master_admin"]:
            raise Forbidden("The Master Admin has all permissions implicitly; roles cannot be changed")
        before = [r["code"] for r in rows(c, "SELECT r.code FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = :u ORDER BY 1", u=uid)]
        _set_roles(c, actor, uid, codes)
        audit(c, "user.roles.update", "user", uid, f"Roles of '{u['username']}' changed", before={"roles": before}, after={"roles": sorted(codes)}, severity="SECURITY")
        return _user_detail(c, uid)


def put_permission_overrides(actor, uid, overrides: list[dict]):
    with tx() as c:
        u = one(c, "SELECT username, is_master_admin FROM users WHERE id = :u FOR UPDATE", u=uid)
        if not u:
            raise NotFound("User")
        if u["is_master_admin"]:
            raise Forbidden("The Master Admin has all permissions implicitly")
        valid = set(rbac.ALL_CODES)
        for o in overrides:
            if o["code"] not in valid or o["effect"] not in ("GRANT", "DENY"):
                raise Invalid(f"Invalid override {o}", "INVALID_PERMISSION")
        before = rows(c, "SELECT permission_code AS code, effect FROM user_permissions WHERE user_id = :u ORDER BY 1", u=uid)
        q(c, "DELETE FROM user_permissions WHERE user_id = :u", u=uid)
        for o in overrides:
            q(c, "INSERT INTO user_permissions (user_id, permission_code, effect, granted_by) VALUES (:u, :p, :e, :g)", u=uid, p=o["code"], e=o["effect"], g=actor["id"])
        rbac.bump_user(c, uid)
        audit(c, "user.permissions.update", "user", uid, f"Permission overrides of '{u['username']}' changed", before={"overrides": before},
              after={"overrides": sorted(overrides, key=lambda o: o["code"])}, severity="SECURITY")
        return _user_detail(c, uid)


def user_lookup(search: str | None):
    with tx() as c:
        return rows(c, """SELECT id, full_name, username, department_id FROM users WHERE is_active AND (CAST(:s AS text) IS NULL OR full_name ILIKE :p OR username ILIKE :p)
                          ORDER BY full_name LIMIT 30""", s=search, p=f"%{search or ''}%")


# ---------------- roles ----------------
def list_roles():
    with tx() as c:
        out = rows(c, "SELECT id, code, name, description, is_system, is_active FROM roles ORDER BY name")
        for r in out:
            r["permissions"] = [x["permission_code"] for x in rows(c, "SELECT permission_code FROM role_permissions WHERE role_id = :r ORDER BY 1", r=r["id"])]
        return out


def _validate_codes(codes):
    bad = set(codes) - set(rbac.ALL_CODES)
    if bad:
        raise Invalid(f"Unknown permissions: {sorted(bad)}", "INVALID_PERMISSION")


def create_role(actor, d):
    _validate_codes(d.get("permissions", []))
    with tx() as c:
        if one(c, "SELECT 1 AS x FROM roles WHERE code = :c", c=d["code"]):
            raise Conflict("DUPLICATE", "Role code already exists")
        r = one(c, "INSERT INTO roles (code, name, description) VALUES (:c, :n, :d) RETURNING id", c=d["code"], n=d["name"], d=d.get("description"))
        for p in set(d.get("permissions", [])):
            q(c, "INSERT INTO role_permissions (role_id, permission_code) VALUES (:r, :p)", r=r["id"], p=p)
        audit(c, "role.create", "role", r["id"], f"Role '{d['code']}' created", after={"permissions": sorted(d.get("permissions", []))}, severity="SECURITY")
    return next(x for x in list_roles() if x["id"] == r["id"])


def update_role(actor, rid, d):
    with tx() as c:
        r = one(c, "SELECT * FROM roles WHERE id = :r FOR UPDATE", r=rid)
        if not r:
            raise NotFound("Role")
        before = [x["permission_code"] for x in rows(c, "SELECT permission_code FROM role_permissions WHERE role_id = :r ORDER BY 1", r=rid)]
        if "name" in d or "description" in d or "is_active" in d:
            q(c, "UPDATE roles SET name = COALESCE(:n, name), description = COALESCE(:d, description), is_active = COALESCE(:a, is_active) WHERE id = :r",
              n=d.get("name"), d=d.get("description"), a=d.get("is_active"), r=rid)
        if "permissions" in d:
            _validate_codes(d["permissions"])
            q(c, "DELETE FROM role_permissions WHERE role_id = :r", r=rid)
            for p in set(d["permissions"]):
                q(c, "INSERT INTO role_permissions (role_id, permission_code) VALUES (:r, :p)", r=rid, p=p)
        rbac.bump_role_members(c, rid)
        after = [x["permission_code"] for x in rows(c, "SELECT permission_code FROM role_permissions WHERE role_id = :r ORDER BY 1", r=rid)]
        audit(c, "role.update", "role", rid, f"Role '{r['code']}' updated", before={"permissions": before, "is_active": r["is_active"]},
              after={"permissions": after, **({"is_active": d["is_active"]} if "is_active" in d else {"is_active": r["is_active"]})}, severity="SECURITY")
    return next(x for x in list_roles() if str(x["id"]) == str(rid))


def list_permissions():
    with tx() as c:
        return rows(c, "SELECT code, module, description, is_approval FROM permissions ORDER BY sort_order")


# ---------------- master data (generic) ----------------
MASTER = {
    "locations": ("locations", ["code", "name", "location_type", "address", "city", "contact_person", "contact_phone", "is_active", "sort_order"], "name"),
    "departments": ("departments", ["code", "name", "head_user_id", "is_active", "sort_order"], "name"),
    "gates": ("gates", ["code", "name", "location_id", "is_active"], "name"),
    "units": ("units_of_measure", ["code", "name", "decimal_places", "is_active", "sort_order"], "sort_order, name"),
}


def md_list(kind, include_inactive=False):
    t, cols, order = MASTER[kind]
    with tx() as c:
        return rows(c, f"SELECT id, {', '.join(cols)} FROM {t} {'' if include_inactive else 'WHERE is_active'} ORDER BY {order}")


def md_create(actor, kind, d):
    t, cols, _ = MASTER[kind]
    data = {k: d[k] for k in cols if k in d}
    with tx() as c:
        names = ", ".join(data)
        vals = ", ".join(f":{k}" for k in data)
        try:
            r = one(c, f"INSERT INTO {t} ({names}) VALUES ({vals}) RETURNING id", **data)
        except Exception as e:
            if "unique" in str(e).lower():
                raise Conflict("DUPLICATE", "Code already exists")
            raise
        audit(c, "masterdata.create", kind, r["id"], f"{kind[:-1].title()} '{data.get('code')}' created", after=data)
        return one(c, f"SELECT id, {', '.join(cols)} FROM {t} WHERE id = :i", i=r["id"])


def md_update(actor, kind, rid, d):
    t, cols, _ = MASTER[kind]
    data = {k: d[k] for k in cols if k in d}
    with tx() as c:
        old = one(c, f"SELECT {', '.join(cols)} FROM {t} WHERE id = :i FOR UPDATE", i=rid)
        if not old:
            raise NotFound(kind[:-1].title())
        if data:
            q(c, f"UPDATE {t} SET {', '.join(f'{k} = :{k}' for k in data)} WHERE id = :i", i=rid, **data)
        b, a = diff(old, data, list(data))
        audit(c, "masterdata.deactivate" if data.get("is_active") is False else "masterdata.update", kind, rid, f"{kind[:-1].title()} '{old['code']}' updated", before=b, after=a)
        return one(c, f"SELECT id, {', '.join(cols)} FROM {t} WHERE id = :i", i=rid)


def lookup_options(code, include_inactive=False):
    with tx() as c:
        return rows(c, f"""SELECT o.id, o.value, o.label, o.sort_order, o.is_active FROM lookup_options o JOIN lookup_lists l ON l.id = o.list_id
                           WHERE l.code = :c {'' if include_inactive else 'AND o.is_active'} ORDER BY o.sort_order, o.label""", c=code)


def lookup_lists():
    with tx() as c:
        return rows(c, "SELECT id, code, name, is_system FROM lookup_lists ORDER BY name")


def lookup_option_upsert(actor, code, d, option_id=None):
    with tx() as c:
        lst = one(c, "SELECT id FROM lookup_lists WHERE code = :c", c=code)
        if not lst:
            raise NotFound("Lookup list")
        if option_id:
            old = one(c, "SELECT * FROM lookup_options WHERE id = :i AND list_id = :l", i=option_id, l=lst["id"])
            if not old:
                raise NotFound("Option")
            q(c, "UPDATE lookup_options SET label = COALESCE(:lb, label), sort_order = COALESCE(:so, sort_order), is_active = COALESCE(:ia, is_active) WHERE id = :i",
              lb=d.get("label"), so=d.get("sort_order"), ia=d.get("is_active"), i=option_id)
            audit(c, "masterdata.update", "lookup_option", option_id, f"Option '{old['value']}' updated", before={"label": old["label"], "is_active": old["is_active"]}, after=d)
            return one(c, "SELECT id, value, label, sort_order, is_active FROM lookup_options WHERE id = :i", i=option_id)
        value = d["value"].strip().upper().replace(" ", "_")
        if one(c, "SELECT 1 AS x FROM lookup_options WHERE list_id = :l AND value = :v", l=lst["id"], v=value):
            raise Conflict("DUPLICATE", "Option value already exists")
        r = one(c, "INSERT INTO lookup_options (list_id, value, label, sort_order) VALUES (:l, :v, :lb, :so) RETURNING id", l=lst["id"], v=value, lb=d["label"], so=d.get("sort_order", 0))
        audit(c, "masterdata.create", "lookup_option", r["id"], f"Option '{value}' added to {code}", after={"value": value, "label": d["label"]})
        return one(c, "SELECT id, value, label, sort_order, is_active FROM lookup_options WHERE id = :i", i=r["id"])


# ---------------- settings ----------------
def put_setting(actor, key, value):
    ss.validate_type(key, value)
    with tx() as c:
        old = one(c, "SELECT value, version FROM system_settings WHERE key = :k FOR UPDATE", k=key)
        q(c, "UPDATE system_settings SET value = CAST(:v AS jsonb), version = version + 1, updated_by = :u, updated_at = now() WHERE key = :k", v=__import__('json').dumps(value), u=actor["id"], k=key)
        audit(c, "setting.update", "setting", key, f"Setting '{key}' changed", before={"value": old["value"]}, after={"value": value})
    ss.invalidate()
    return {"key": key, "value": value}
