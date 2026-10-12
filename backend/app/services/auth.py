import hashlib
from datetime import datetime, timedelta, timezone

from ..core import ctx, rbac, settings_store as ss
from ..core.audit import audit
from ..core.config import settings
from ..core.db import J, one, q, rows, scalar, tx
from ..core.errors import AppError, Invalid
from ..core.security import (check_password_policy, decrypt_secret, encrypt_secret, hash_password, make_access_token, new_recovery_codes,
                             new_refresh_token, new_totp_secret, sha256_hex, totp_uri, verify_password, verify_totp)

_DUMMY = hash_password("dummy-password-for-timing-0")


def _now():
    return datetime.now(timezone.utc)


def _new_session(c, user_id, family_id=None, parent=None, scope="full"):
    r = ctx.get()
    tok = new_refresh_token()
    s = one(c, """INSERT INTO auth_sessions (user_id, family_id, parent_session_id, refresh_token_hash, platform, device_label, client_version,
                                             ip, user_agent, scope, expires_at)
                  VALUES (:u, COALESCE(CAST(:f AS uuid), gen_random_uuid()), CAST(:p AS uuid), :h, :pl, :dl, :cv, CAST(:ip AS inet), :ua, :sc, :exp)
                  RETURNING id, family_id""",
            u=user_id, f=family_id, p=parent, h=sha256_hex(tok), pl=r.platform or "web", dl=(r.user_agent or "")[:120] or None,
            cv=r.client_version, ip=r.ip, ua=(r.user_agent or "")[:300] or None, sc=scope,
            exp=_now() + timedelta(days=settings.refresh_token_days if scope == "full" else 1))
    return tok, s


def _record_failure(username, user_id, reason, lock_user=False):
    with tx() as c:
        r = ctx.get()
        q(c, """INSERT INTO login_attempts (username_attempted, user_id, ip, success, failure_reason, platform)
                VALUES (:u, :uid, CAST(:ip AS inet), false, :r, :p)""", u=username[:80], uid=user_id, ip=r.ip, r=reason, p=r.platform)
        sev, locked = "SECURITY", False
        if user_id:
            n = scalar(c, "UPDATE users SET failed_login_count = failed_login_count + 1 WHERE id = :u RETURNING failed_login_count", u=user_id)
            if n >= ss.get("security.max_failed_logins", c):
                q(c, "UPDATE users SET locked_until = :t, failed_login_count = 0 WHERE id = :u", u=user_id,
                  t=_now() + timedelta(minutes=ss.get("security.lock_minutes", c)))
                locked = True
        audit(c, "auth.lockout" if locked else "auth.login.failure", "user", user_id, f"Failed login for '{username}': {reason}",
              severity=sev, actor_username=username)


def login(username: str, password: str, totp: str | None = None, recovery_code: str | None = None) -> dict:
    username = (username or "").strip().lower()
    r = ctx.get()
    with tx() as c:
        if scalar(c, """SELECT count(*) FROM login_attempts WHERE ip = CAST(:ip AS inet) AND NOT success
                        AND occurred_at > now() - interval '15 minutes'""", ip=r.ip) >= ss.get("security.ip_failures_per_15min", c):
            raise AppError("RATE_LIMITED", "Too many failed attempts. Try again later.", 429)
        u = one(c, "SELECT * FROM users WHERE username = :u", u=username)
    if not u:
        verify_password(password, _DUMMY)
        _record_failure(username, None, "unknown_user")
        raise AppError("INVALID_CREDENTIALS", "Invalid username or password", 401)
    if u["locked_until"] and u["locked_until"] > _now():
        raise AppError("ACCOUNT_LOCKED", "Account temporarily locked. Try again later.", 423)
    if not verify_password(password, u["password_hash"]) or not u["is_active"]:
        _record_failure(username, str(u["id"]), "bad_password" if u["is_active"] else "inactive")
        raise AppError("INVALID_CREDENTIALS", "Invalid username or password", 401)
    mfa_required_setup = False
    if u["mfa_enabled"]:
        if not (totp or recovery_code):
            raise AppError("MFA_REQUIRED", "A verification code is required", 401)
        ok = False
        with tx() as c:
            if totp and verify_totp(decrypt_secret(u["mfa_secret_enc"]), totp):
                ok = True
            elif recovery_code:
                h = sha256_hex(recovery_code.strip().lower())
                codes = list(u["mfa_recovery_hashes"] or [])
                if h in codes:
                    codes.remove(h)
                    q(c, "UPDATE users SET mfa_recovery_hashes = CAST(:c AS jsonb) WHERE id = :u", c=J(codes), u=u["id"])
                    audit(c, "auth.mfa.recovery_used", "user", u["id"], "MFA recovery code used", severity="SECURITY", actor_id=u["id"], actor_username=u["username"])
                    ok = True
        if not ok:
            _record_failure(username, str(u["id"]), "bad_mfa")
            raise AppError("INVALID_MFA", "Invalid verification code", 401)
    elif u["is_master_admin"] and ss.get("security.mfa_required_master_admin"):
        mfa_required_setup = True
    with tx() as c:
        q(c, "UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() WHERE id = :u", u=u["id"])
        q(c, """INSERT INTO login_attempts (username_attempted, user_id, ip, success, platform) VALUES (:n, :u, CAST(:ip AS inet), true, :p)""",
          n=username, u=u["id"], ip=r.ip, p=r.platform)
        if mfa_required_setup:
            _tok, s = _new_session(c, u["id"], scope="mfa_setup")
            audit(c, "auth.login.success", "user", u["id"], "Login (MFA setup required)", actor_id=u["id"], actor_username=u["username"])
            return {"mfa_setup_required": True, "access_token": make_access_token(str(u["id"]), str(s["id"]), "mfa_setup"),
                    "token_type": "bearer", "expires_in": settings.setup_token_minutes * 60}
        refresh, s = _new_session(c, u["id"])
        audit(c, "auth.login.success", "user", u["id"], f"User '{u['username']}' logged in", actor_id=u["id"], actor_username=u["username"])
    return {"access_token": make_access_token(str(u["id"]), str(s["id"])), "refresh_token": refresh, "token_type": "bearer",
            "expires_in": settings.access_token_minutes * 60, "must_change_password": u["must_change_password"]}


def refresh(token: str) -> dict:
    h = sha256_hex(token or "")
    with tx() as c:
        s = one(c, "SELECT * FROM auth_sessions WHERE refresh_token_hash = :h FOR UPDATE", h=h)
        if not s or s["scope"] != "full":
            raise AppError("INVALID_REFRESH", "Session expired. Please sign in again.", 401)
    if s["rotated_at"] is not None:   # reuse of a rotated token => theft signal: revoke the whole family
        with tx() as c:
            q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'token_reuse' WHERE family_id = :f AND revoked_at IS NULL", f=s["family_id"])
            audit(c, "auth.token.reuse_detected", "user", s["user_id"], "Refresh token reuse detected; session family revoked", severity="SECURITY", actor_id=s["user_id"])
        raise AppError("INVALID_REFRESH", "Session expired. Please sign in again.", 401)
    if s["revoked_at"] or s["expires_at"] < _now():
        raise AppError("INVALID_REFRESH", "Session expired. Please sign in again.", 401)
    with tx() as c:
        u = one(c, "SELECT id, username, is_active, must_change_password FROM users WHERE id = :u", u=s["user_id"])
        if not u or not u["is_active"]:
            raise AppError("USER_INACTIVE", "Account is not active", 401)
        got = one(c, "UPDATE auth_sessions SET rotated_at = now(), last_used_at = now() WHERE id = :i AND rotated_at IS NULL RETURNING id", i=s["id"])
        if not got:   # lost a race with a concurrent refresh using the same token
            raise AppError("INVALID_REFRESH", "Session expired. Please sign in again.", 401)
        tok, ns = _new_session(c, s["user_id"], family_id=str(s["family_id"]), parent=str(s["id"]))
    return {"access_token": make_access_token(str(u["id"]), str(ns["id"])), "refresh_token": tok, "token_type": "bearer",
            "expires_in": settings.access_token_minutes * 60, "must_change_password": u["must_change_password"]}


def logout(user: dict, all_sessions=False):
    with tx() as c:
        if all_sessions:
            q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'logout_all' WHERE user_id = :u AND revoked_at IS NULL", u=user["id"])
        else:
            fam = scalar(c, "SELECT family_id FROM auth_sessions WHERE id = :s", s=user["session_id"])
            q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'logout' WHERE family_id = :f AND revoked_at IS NULL", f=fam)
        audit(c, "auth.logout", "user", user["id"], "User logged out" + (" everywhere" if all_sessions else ""))


def change_password(user: dict, current: str, new: str):
    with tx() as c:
        u = one(c, "SELECT * FROM users WHERE id = :u FOR UPDATE", u=user["id"])
        if not verify_password(current, u["password_hash"]):
            raise AppError("INVALID_CREDENTIALS", "Current password is incorrect", 401)
        check_password_policy(new, ss.get("security.password_min_length", c), u["username"])
        for h in rows(c, "SELECT password_hash FROM user_password_history WHERE user_id = :u ORDER BY created_at DESC LIMIT 5", u=u["id"]):
            if verify_password(new, h["password_hash"]):
                raise Invalid("You cannot reuse one of your last 5 passwords", "PASSWORD_REUSE")
        nh = hash_password(new)
        q(c, "INSERT INTO user_password_history (user_id, password_hash) VALUES (:u, :h)", u=u["id"], h=u["password_hash"])
        q(c, "UPDATE users SET password_hash = :h, password_changed_at = now(), must_change_password = false WHERE id = :u", h=nh, u=u["id"])
        q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'password_change' WHERE user_id = :u AND id <> :s AND revoked_at IS NULL",
          u=u["id"], s=user["session_id"])
        audit(c, "auth.password.change", "user", u["id"], "Password changed", severity="SECURITY")


def mfa_setup(user: dict) -> dict:
    with tx() as c:
        u = one(c, "SELECT mfa_enabled, username FROM users WHERE id = :u FOR UPDATE", u=user["id"])
        if u["mfa_enabled"]:
            raise AppError("MFA_ALREADY_ENABLED", "MFA is already enabled", 409)
        secret = new_totp_secret()
        q(c, "UPDATE users SET mfa_secret_enc = :s WHERE id = :u", s=encrypt_secret(secret), u=user["id"])
        audit(c, "auth.mfa.setup_started", "user", user["id"], "MFA setup started", severity="SECURITY")
    return {"secret": secret, "otpauth_uri": totp_uri(secret, u["username"])}


def mfa_verify(user: dict, code: str) -> dict:
    with tx() as c:
        u = one(c, "SELECT mfa_secret_enc, mfa_enabled FROM users WHERE id = :u FOR UPDATE", u=user["id"])
        if not u["mfa_secret_enc"] or u["mfa_enabled"]:
            raise AppError("MFA_NOT_PENDING", "No MFA setup in progress", 409)
        if not verify_totp(decrypt_secret(u["mfa_secret_enc"]), code):
            raise AppError("INVALID_MFA", "Invalid verification code", 401)
        codes = new_recovery_codes()
        q(c, "UPDATE users SET mfa_enabled = true, mfa_recovery_hashes = CAST(:h AS jsonb) WHERE id = :u",
          h=J([sha256_hex(x) for x in codes]), u=user["id"])
        audit(c, "auth.mfa.enable", "user", user["id"], "MFA enabled", severity="SECURITY")
        # leave the limited setup session; the user signs in again with MFA
        q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'mfa_enabled' WHERE id = :s AND scope <> 'full'", s=user["session_id"])
    return {"recovery_codes": codes}


def mfa_disable(user: dict, password: str):
    with tx() as c:
        u = one(c, "SELECT password_hash, is_master_admin FROM users WHERE id = :u FOR UPDATE", u=user["id"])
        if u["is_master_admin"] and ss.get("security.mfa_required_master_admin"):
            raise AppError("MFA_REQUIRED_FOR_ROLE", "MFA cannot be disabled for the Master Admin", 403)
        if not verify_password(password, u["password_hash"]):
            raise AppError("INVALID_CREDENTIALS", "Password is incorrect", 401)
        q(c, "UPDATE users SET mfa_enabled = false, mfa_secret_enc = NULL, mfa_recovery_hashes = NULL WHERE id = :u", u=user["id"])
        audit(c, "auth.mfa.disable", "user", user["id"], "MFA disabled", severity="SECURITY")


def sessions(user: dict):
    with tx() as c:
        return rows(c, """SELECT id, platform, device_label, client_version, ip::text AS ip, created_at, last_used_at,
                          (id = :s) AS current FROM auth_sessions WHERE user_id = :u AND revoked_at IS NULL AND rotated_at IS NULL
                          AND scope = 'full' ORDER BY last_used_at DESC""", u=user["id"], s=user["session_id"])


def revoke_session(user: dict, session_id: str):
    with tx() as c:
        fam = scalar(c, "SELECT family_id FROM auth_sessions WHERE id = :i AND user_id = :u", i=session_id, u=user["id"])
        if fam:
            q(c, "UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'user_revoked' WHERE family_id = :f AND revoked_at IS NULL", f=fam)
            audit(c, "auth.session.revoke", "session", session_id, "Session revoked by user")
