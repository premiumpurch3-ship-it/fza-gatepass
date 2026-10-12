"""RBAC: permission catalogue (master-prompt codes), seeded roles, effective-permission resolution."""
from .db import one, q, rows

PERMISSIONS = [
    # code, module, description, is_approval
    ("dashboard.view", "Dashboard", "View dashboard", False),
    ("gatepass.create", "Gate Pass", "Create gate passes", False),
    ("gatepass.view", "Gate Pass", "View all gate passes (creators always see their own)", False),
    ("gatepass.edit", "Gate Pass", "Edit own draft/rejected gate passes", False),
    ("gatepass.submit", "Gate Pass", "Submit gate passes for approval", False),
    ("gatepass.cancel", "Gate Pass", "Cancel own gate passes", False),
    ("gatepass.cancel.any", "Gate Pass", "Cancel any gate pass before completion", False),
    ("approval.level1", "Approval", "Level 1 approval of outward passes", True),
    ("approval.level2", "Approval", "Level 2 approval of outward passes", True),
    ("inward.approve", "Approval", "Approve inward passes", True),
    ("security.gateout", "Security", "Record Gate Out", False),
    ("security.gatein", "Security", "Record Gate In and returned quantities", False),
    ("admin.verify", "Security", "Admin/Audit verification of gate passes", False),
    ("return.view", "Returns", "View returnable tracking", False),
    ("return.close", "Returns", "Close/reverse return postings (Admin/Audit)", False),
    ("return.writeoff", "Returns", "Write off unreturned quantities (Admin/Audit)", False),
    ("attachment.upload", "Attachments", "Upload attachments and camera photos", False),
    ("attachment.view", "Attachments", "View/download attachments", False),
    ("attachment.delete", "Attachments", "Delete own attachments before submission", False),
    ("reports.view", "Reports", "View reports", False),
    ("reports.export", "Reports", "Export reports", False),
    ("admin.users", "Administration", "Manage users", False),
    ("admin.roles", "Administration", "Manage roles and permissions", False),
    ("admin.forms", "Administration", "Manage forms and form versions", False),
    ("admin.settings", "Administration", "Manage settings, locations, gates, notifications", False),
    ("audit.view", "Audit", "View audit logs", False),
]
ALL_CODES = [p[0] for p in PERMISSIONS]

ROLES = {
    "gatepass_creator": ("Gate Pass Creator", ["dashboard.view", "gatepass.create", "gatepass.edit", "gatepass.submit", "gatepass.cancel",
                                               "attachment.upload", "attachment.view", "attachment.delete", "return.view"]),
    "approver_l1": ("Level 1 Approver", ["dashboard.view", "approval.level1", "attachment.view", "return.view"]),
    "approver_l2": ("Level 2 Approver", ["dashboard.view", "approval.level2", "attachment.view", "return.view"]),
    "inward_approver": ("Inward Approver", ["dashboard.view", "inward.approve", "attachment.view", "return.view"]),
    "security_officer": ("Security Officer", ["dashboard.view", "security.gateout", "security.gatein", "attachment.upload",
                                              "attachment.view", "return.view"]),
    "admin_auditor": ("Admin / Audit", ["dashboard.view", "gatepass.view", "attachment.view", "return.view", "return.close",
                                        "return.writeoff", "admin.verify", "reports.view", "reports.export", "audit.view"]),
    "reporter": ("Reporter", ["dashboard.view", "gatepass.view", "attachment.view", "return.view", "reports.view", "reports.export"]),
}


def seed(c):
    for i, (code, mod, desc, appr) in enumerate(PERMISSIONS):
        q(c, """INSERT INTO permissions (code, module, description, is_approval, sort_order) VALUES (:c, :m, :d, :a, :s)
                ON CONFLICT (code) DO UPDATE SET module = :m, description = :d, is_approval = :a, sort_order = :s""",
          c=code, m=mod, d=desc, a=appr, s=i)
    for rcode, (name, perms) in ROLES.items():
        r = one(c, """INSERT INTO roles (code, name, is_system) VALUES (:c, :n, true)
                      ON CONFLICT (code) DO UPDATE SET name = :n RETURNING id""", c=rcode, n=name)
        if one(c, "SELECT 1 AS x FROM role_permissions WHERE role_id = :r LIMIT 1", r=r["id"]) is None:
            for p in perms:
                q(c, "INSERT INTO role_permissions (role_id, permission_code) VALUES (:r, :p) ON CONFLICT DO NOTHING", r=r["id"], p=p)


_cache: dict = {}


def effective_permissions(c, user: dict) -> set[str]:
    if not user["is_active"]:
        return set()
    if user["is_master_admin"]:
        return set(ALL_CODES)
    key = (str(user["id"]), user["authz_version"])
    hit = _cache.get(key)
    if hit is not None:
        return hit
    granted = {r["permission_code"] for r in rows(c, """
        SELECT rp.permission_code FROM user_roles ur JOIN roles r ON r.id = ur.role_id AND r.is_active
        JOIN role_permissions rp ON rp.role_id = r.id WHERE ur.user_id = :u""", u=user["id"])}
    for r in rows(c, "SELECT permission_code, effect FROM user_permissions WHERE user_id = :u", u=user["id"]):
        (granted.add if r["effect"] == "GRANT" else granted.discard)(r["permission_code"])
    if len(_cache) > 5000:
        _cache.clear()
    _cache[key] = granted
    return granted


def bump_user(c, user_id):
    q(c, "UPDATE users SET authz_version = authz_version + 1 WHERE id = :u", u=user_id)


def bump_role_members(c, role_id):
    q(c, "UPDATE users SET authz_version = authz_version + 1 WHERE id IN (SELECT user_id FROM user_roles WHERE role_id = :r)", r=role_id)
