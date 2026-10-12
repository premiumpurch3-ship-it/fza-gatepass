"""Server CLI. Usage:
  python -m app.cli seed                      # idempotent reference data, roles, permissions, settings, form v1
  python -m app.cli create-master-admin       # interactive; also enrols TOTP MFA
  python -m app.cli reset-master-admin        # recovery of the Master Admin password (needs shell access to the server)
  python -m app.cli apply-grants              # least-privilege DB roles (production)
  python -m app.cli seed-dev-users            # DEVELOPMENT ONLY demo users (refuses to run when ENV=production)
"""
import getpass
import sys

from .core import rbac, settings_store as ss
from .core.audit import audit
from .core.config import settings
from .core.db import J, one, q, tx
from .core.security import (check_password_policy, encrypt_secret, hash_password, new_recovery_codes, new_totp_secret, sha256_hex, totp_uri, verify_totp)
from .services import forms_seed


def apply_grants():
    """Create/refresh the restricted application and backup roles. Passwords come from APP_DB_PASSWORD / BACKUP_DB_PASSWORD."""
    import os
    from pathlib import Path
    app_pw, bk_pw = os.environ.get("APP_DB_PASSWORD"), os.environ.get("BACKUP_DB_PASSWORD")
    sql = (Path(__file__).resolve().parents[1] / "sql" / "grants.sql").read_text()
    with tx() as c:
        c.connection.driver_connection.execute(sql)
        for role, pw in (("gatepass_app", app_pw), ("gatepass_backup", bk_pw)):
            if pw:
                q(c, "SELECT set_config('gp.pw', :p, true)", p=pw)
                q(c, f"DO $$ BEGIN EXECUTE format('ALTER ROLE {role} PASSWORD %L', current_setting('gp.pw')); END $$")
    print("Grants applied.", "(set APP_DB_PASSWORD/BACKUP_DB_PASSWORD to set role passwords)" if not (app_pw and bk_pw) else "")


def seed():
    with tx() as c:
        rbac.seed(c)
        ss.seed_defaults(c)
        forms_seed.seed_reference_data(c)
        forms_seed.seed_forms(c)
    print("Seed complete.")


def _create_master(username, full_name, password, secret=None, code=None, interactive=True):
    with tx() as c:
        if one(c, "SELECT 1 AS x FROM users WHERE is_master_admin"):
            raise SystemExit("A Master Admin already exists. Use reset-master-admin for recovery.")
        check_password_policy(password, 12, username)
        secret = secret or new_totp_secret()
        if interactive:
            print("\nScan this URI in an authenticator app (or enter the secret manually):\n ", totp_uri(secret, username), "\n  secret:", secret)
            code = input("Enter the 6-digit code to confirm MFA: ").strip()
        if not verify_totp(secret, code or ""):
            raise SystemExit("Invalid MFA code. Nothing was created.")
        recovery = new_recovery_codes()
        u = one(c, """INSERT INTO users (username, full_name, password_hash, is_master_admin, must_change_password, mfa_enabled, mfa_secret_enc, mfa_recovery_hashes)
                      VALUES (:u, :n, :p, true, false, true, :s, CAST(:r AS jsonb)) RETURNING id""",
                u=username.lower(), n=full_name, p=hash_password(password), s=encrypt_secret(secret), r=J([sha256_hex(x) for x in recovery]))
        audit(c, "user.create", "user", u["id"], "Master Admin created via CLI", severity="SECURITY", actor_username="cli")
    return recovery


def create_master_admin():
    username = input("Master Admin username [admin]: ").strip() or "admin"
    full = input("Full name [Master Administrator]: ").strip() or "Master Administrator"
    pw = getpass.getpass("Password (min 12 chars): ")
    if pw != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match")
    codes = _create_master(username, full, pw)
    print("\nMaster Admin created. SAVE THESE ONE-TIME RECOVERY CODES SOMEWHERE SAFE:\n ", "\n  ".join(codes))


def reset_master_admin():
    with tx() as c:
        u = one(c, "SELECT id, username FROM users WHERE is_master_admin")
        if not u:
            raise SystemExit("No Master Admin exists")
    pw = getpass.getpass(f"New password for '{u['username']}' (min 12 chars): ")
    if pw != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match")
    check_password_policy(pw, 12, u["username"])
    with tx() as c:
        q(c, "UPDATE users SET password_hash = :h, failed_login_count = 0, locked_until = NULL, must_change_password = false WHERE id = :u", h=hash_password(pw), u=u["id"])
        q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'master_reset' WHERE user_id = :u AND revoked_at IS NULL", u=u["id"])
        audit(c, "auth.password.reset", "user", u["id"], "Master Admin password reset via CLI", severity="SECURITY", actor_username="cli")
    print("Password reset. MFA is unchanged.")


DEV_USERS = [("creator", "Ahmed Creator", "gatepass_creator"), ("approver1", "Bilal Level-1", "approver_l1"), ("approver2", "Chaudhry Level-2", "approver_l2"),
             ("inward_appr", "Danish Inward Approver", "inward_approver"), ("security", "Farhan Security", "security_officer"), ("audit", "Gul Admin-Audit", "admin_auditor")]


def seed_dev_users():
    if settings.env == "production":
        raise SystemExit("Refusing to create development users in production")
    pw = "DevPassw0rd!"
    with tx() as c:
        for un, name, role in DEV_USERS:
            if one(c, "SELECT 1 AS x FROM users WHERE username = :u", u=un):
                continue
            u = one(c, "INSERT INTO users (username, full_name, email, password_hash, must_change_password) VALUES (:u, :n, :e, :p, false) RETURNING id",
                    u=un, n=name, e=f"{un}@example.test", p=hash_password(pw))
            q(c, "INSERT INTO user_roles (user_id, role_id) SELECT :u, id FROM roles WHERE code = :r", u=u["id"], r=role)
        loc = one(c, "SELECT id FROM locations WHERE code = 'HQ'")
        if not loc:
            q(c, "INSERT INTO locations (code, name, location_type, city) VALUES ('HQ', 'Head Office', 'EXTERNAL', 'Karachi'), ('SVC', 'Service Center', 'EXTERNAL', 'Lahore') ON CONFLICT DO NOTHING")
    print(f"Development users created (password: {pw}): " + ", ".join(u[0] for u in DEV_USERS))


if __name__ == "__main__":
    cmds = {"apply-grants": apply_grants, "seed": seed, "create-master-admin": create_master_admin, "reset-master-admin": reset_master_admin, "seed-dev-users": seed_dev_users}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        raise SystemExit(__doc__)
    cmds[sys.argv[1]]()
