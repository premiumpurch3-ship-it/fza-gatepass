import pyotp
import pytest

from tests.conftest import PW, U, _login
from app.core.db import one, q, tx


def test_login_success_failure_and_audit(client, make_user):
    u = make_user(["gatepass_creator"])
    assert _login(client, u.username, "wrong-password1").status_code == 401
    assert _login(client, "nobody-here", PW).json()["code"] == "INVALID_CREDENTIALS"      # no username enumeration
    r = _login(client, u.username)
    assert r.status_code == 200 and r.json()["refresh_token"] and r.json()["access_token"]
    m = make_user(master=True)
    log = m.get("/audit-logs", params={"action": "auth.login.failure"}).json()
    assert log["total"] >= 2 and all(i["severity"] == "SECURITY" for i in log["items"])


def test_account_lockout_after_repeated_failures(client, make_user):
    u = make_user(["gatepass_creator"])
    for _ in range(5):
        assert _login(client, u.username, "bad-password-1").status_code == 401
    assert _login(client, u.username, PW).status_code == 423                               # locked even with the right password


def test_refresh_rotation_and_reuse_detection(client, make_user):
    u = make_user(["gatepass_creator"])
    first = _login(client, u.username).json()
    r1 = client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert r1.status_code == 200 and r1.json()["refresh_token"] != first["refresh_token"]
    # replaying the old token is theft: whole family is revoked, including the new token
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": r1.json()["refresh_token"]}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {r1.json()['access_token']}"}).status_code == 401


def test_web_refresh_uses_httponly_cookie_and_csrf_header(client, make_user):
    u = make_user(["gatepass_creator"])
    r = client.post("/api/v1/auth/login", json={"username": u.username, "password": PW}, headers={"x-client-platform": "web"})
    assert r.status_code == 200 and "refresh_token" not in r.json() and "httponly" in r.headers["set-cookie"].lower()
    assert client.post("/api/v1/auth/refresh", headers={"x-client-platform": "web"}).status_code == 403
    ok = client.post("/api/v1/auth/refresh", headers={"x-client-platform": "web", "x-requested-with": "fzagp"})
    assert ok.status_code == 200
    client.cookies.clear()


def test_master_admin_requires_mfa(client):
    """Master Admin without MFA gets a limited setup token only; after enrolment MFA is mandatory at login."""
    from app.core.security import hash_password
    from tests import conftest
    had_master = bool(conftest._MASTER)
    with tx() as c:       # LOCAL: the setting is reverted at commit, never leaks into the connection pool
        q(c, "SET LOCAL session_replication_role = replica")
        q(c, "UPDATE users SET is_master_admin = false WHERE is_master_admin")
        q(c, "DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE username = 'mfa_master')")
        q(c, "DELETE FROM users WHERE username = 'mfa_master'")
        u = one(c, """INSERT INTO users (username, full_name, password_hash, is_master_admin, must_change_password) VALUES ('mfa_master', 'MFA Master', :p, true, false) RETURNING id""", p=hash_password(PW))
    r = _login(client, "mfa_master")
    assert r.status_code == 200 and r.json()["mfa_setup_required"] is True and "refresh_token" not in r.json()
    tok = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/api/v1/users", headers=tok).status_code == 403                    # limited token cannot use the app
    secret = client.post("/api/v1/auth/mfa/setup", headers=tok).json()["secret"]
    assert client.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers=tok).status_code == 401
    v = client.post("/api/v1/auth/mfa/verify", json={"code": pyotp.TOTP(secret).now()}, headers=tok)
    assert v.status_code == 200 and len(v.json()["recovery_codes"]) == 8
    assert _login(client, "mfa_master").json()["code"] == "MFA_REQUIRED"
    assert _login(client, "mfa_master", totp="000000").status_code == 401
    ok = _login(client, "mfa_master", totp=pyotp.TOTP(secret).now())
    assert ok.status_code == 200 and "refresh_token" in ok.json()
    # MFA cannot be disabled for the Master Admin
    h = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    assert client.post("/api/v1/auth/mfa/disable", json={"password": PW}, headers=h).status_code == 403
    # restore the shared fixture master for other tests
    with tx() as c:
        q(c, "SET LOCAL session_replication_role = replica")
        q(c, "UPDATE users SET is_master_admin = false WHERE username = 'mfa_master'")
        if had_master:
            q(c, "UPDATE users SET is_master_admin = true WHERE username = :u", u=conftest._MASTER["username"])
    if not had_master:
        conftest._MASTER.clear()


def test_only_one_master_admin_and_it_cannot_be_deactivated(world):
    w = world
    with pytest.raises(Exception, match="uq_users__single_master"):          # a second master cannot be inserted
        with tx() as c:
            q(c, "INSERT INTO users (username, full_name, password_hash, is_master_admin) VALUES ('second_master', 'X', 'x', true)")
    with pytest.raises(Exception, match="immutable"):                         # nor can a normal user be promoted
        with tx() as c:
            q(c, "UPDATE users SET is_master_admin = true WHERE username = :u", u=w.creator.username)
    r = w.master.post(f"/users/{w.master.id}/deactivate")
    assert r.status_code == 403
    with pytest.raises(Exception, match="master admin cannot be deactivated|immutable"):
        with tx() as c:
            q(c, "UPDATE users SET is_active = false WHERE id = :u", u=w.master.id)


def test_user_admin_flow_create_roles_permissions_and_deactivate(world):
    w = world
    r = w.master.post("/users", {"username": "newuser", "full_name": "New User", "password": "SomePassw0rd1", "role_codes": ["gatepass_creator"]})
    assert r.status_code == 201 and r.json()["roles"] == ["gatepass_creator"]
    uid = r.json()["id"]
    assert w.creator.post("/users", {"username": "x1x", "full_name": "X", "password": "SomePassw0rd1"}).status_code == 403        # admin.users enforced server side
    assert w.master.post("/users", {"username": "newuser", "full_name": "Dup", "password": "SomePassw0rd1"}).status_code == 409
    assert w.master.post("/users", {"username": "weakpw", "full_name": "W", "password": "short"}).status_code == 422
    nu = U(w.master.client, uid, "newuser")
    nu.token = _login(w.master.client, "newuser", "SomePassw0rd1").json()["access_token"]
    assert nu.get("/auth/me").json()["permissions"].count("approval.level1") == 0
    # grant Level 1 approval via override: effective immediately, no re-login needed
    r = w.master.put(f"/users/{uid}/permissions", {"overrides": [{"code": "approval.level1", "effect": "GRANT"}]})
    assert r.status_code == 200 and "approval.level1" in r.json()["effective_permissions"]
    assert "approval.level1" in nu.get("/auth/me").json()["permissions"]
    # role change and DENY override
    w.master.put(f"/users/{uid}/roles", {"role_codes": ["approver_l1"]})
    w.master.put(f"/users/{uid}/permissions", {"overrides": [{"code": "approval.level1", "effect": "DENY"}]})
    assert "approval.level1" not in nu.get("/auth/me").json()["permissions"]
    # reset password forces change; deactivate kills sessions immediately
    assert "temporary_password" in w.master.post(f"/users/{uid}/reset-password").json()
    assert nu.get("/auth/me").status_code == 401
    w.master.post(f"/users/{uid}/deactivate")
    assert _login(w.master.client, "newuser", "SomePassw0rd1").status_code == 401
    audit = w.master.get("/audit-logs", params={"entity_type": "user"}).json()
    assert {"user.create", "user.permissions.update", "user.roles.update", "user.deactivate"} <= {a["action"] for a in audit["items"]}


def test_every_route_is_public_or_permission_protected():
    """Deny-by-default guard: any new route must declare auth, or be on the short public allow-list."""
    from fastapi.routing import APIRoute
    from app.main import app
    public = {"/health", "/health/ready", "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/settings/public", "/api/v1/storage/local/{token}"}
    missing = []
    for r in app.routes:
        if not isinstance(r, APIRoute) or r.path in public:
            continue
        names = {getattr(d.call, "__name__", "") for d in r.dependant.dependencies}
        deep = set()
        stack = list(r.dependant.dependencies)
        while stack:
            d = stack.pop()
            deep.add(getattr(d.call, "__name__", ""))
            stack += d.dependencies
        if not deep & {"current_user", "setup_or_full_user", "dep"}:
            missing.append(r.path)
    assert missing == [], missing


def test_rbac_matrix_on_endpoints(world):
    w = world
    checks = [("get", "/users", w.creator, 403), ("get", "/audit-logs", w.creator, 403), ("get", "/audit-logs", w.audit, 200), ("get", "/roles", w.audit, 403),
              ("get", "/reports", w.creator, 403), ("get", "/reports", w.reporter, 200), ("get", "/returns", w.reporter, 200), ("get", "/forms", w.creator, 403),
              ("get", "/settings", w.audit, 403), ("get", "/security/awaiting-out", w.creator, 403), ("get", "/security/awaiting-out", w.sec, 200),
              ("get", "/dashboard/summary", w.creator, 200), ("get", "/reports/audit", w.reporter, 403), ("get", "/reports/audit", w.audit, 200)]
    for method, url, user, expect in checks:
        assert getattr(user, method)(url).status_code == expect, (url, user.username)
    assert w.reporter.get("/reports/outward/export", params={"format": "csv"}).status_code == 200
    assert w.audit.get("/reports/outward/export", params={"format": "csv"}).status_code == 200
    r = w.master.put("/users/%s/permissions" % w.reporter.id, {"overrides": [{"code": "reports.export", "effect": "DENY"}]})
    assert w.reporter.get("/reports/outward/export", params={"format": "csv"}).status_code == 403
