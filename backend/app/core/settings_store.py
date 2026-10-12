import json
import time
from .db import J, one, q, rows, tx
from .errors import Invalid

DEFAULTS = {
    "company.name": ("MTJ-Clothing", "string", "company", True),
    "company.logo_key": (None, "string", "company", True),
    "numbering.format": ("GP-{YYYY}-{SEQ:6}", "string", "numbering", False),
    "i18n.timezone": ("Asia/Karachi", "string", "i18n", True),
    "i18n.date_format": ("dd-MMM-yyyy", "string", "i18n", True),
    "i18n.time_format": ("12h", "string", "i18n", True),
    "approval.allow_self_approval": (False, "bool", "approval", False),
    "approval.allow_same_user_both_levels": (False, "bool", "approval", False),
    "approval.require_comment_on_reject": (True, "bool", "approval", False),
    "approval.require_comment_on_approve": (False, "bool", "approval", False),
    "workflow.auto_close_after_complete": (True, "bool", "workflow", False),
    "return.require_expected_date": (True, "bool", "returns", False),
    "return.reminder_offsets_days": ([0, 3, 7], "list", "returns", False),
    "return.reminder_repeat_days": (7, "int", "returns", False),
    "attachments.max_image_mb": (15, "int", "attachments", True),
    "attachments.max_video_mb": (500, "int", "attachments", True),
    "attachments.max_document_mb": (25, "int", "attachments", True),
    "attachments.max_files_per_pass": (30, "int", "attachments", True),
    "attachments.allowed_extensions": (["jpg", "jpeg", "png", "heic", "pdf", "doc", "docx", "xls", "xlsx", "mp4", "mov", "webm", "m4v"],
                                      "list", "attachments", True),
    "retention.video_days": (1095, "int", "retention", False),
    "security.password_min_length": (10, "int", "security", False),
    "security.max_failed_logins": (5, "int", "security", False),
    "security.lock_minutes": (15, "int", "security", False),
    "security.ip_failures_per_15min": (30, "int", "security", False),
    "security.mfa_required_master_admin": (True, "bool", "security", False),
    "client.min_version": ({"web": "1.0.0", "electron": "1.0.0", "android": "1.0.0", "ios": "1.0.0"}, "json", "client", True),
    "forms.mandatory_fields": (["location_id", "responsible"], "list", "forms", False),
    "notifications.email_enabled": (True, "bool", "notifications", False),
}
_cache: dict = {}
_TTL = 5.0


def seed_defaults(c):
    for k, (v, t, cat, pub) in DEFAULTS.items():
        q(c, """INSERT INTO system_settings (key, value, value_type, category, is_public)
                VALUES (:k, CAST(:v AS jsonb), :t, :cat, :pub) ON CONFLICT (key) DO NOTHING""", k=k, v=json.dumps(v), t=t, cat=cat, pub=pub)


def get(key: str, c=None):
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and now - hit[0] < _TTL and c is None:
        return hit[1]
    def fetch(cc):
        r = one(cc, "SELECT value FROM system_settings WHERE key = :k", k=key)
        return r["value"] if r else (DEFAULTS.get(key, (None,))[0])
    if c is not None:
        return fetch(c)
    with tx() as cc:
        v = fetch(cc)
    _cache[key] = (now, v)
    return v


def invalidate():
    _cache.clear()


def list_all(c, public_only=False):
    return rows(c, "SELECT key, value, value_type, category, description, is_public, version, updated_at FROM system_settings "
                   + ("WHERE is_public " if public_only else "") + "ORDER BY category, key")


def validate_type(key: str, value):
    spec = DEFAULTS.get(key)
    if not spec:
        raise Invalid(f"Unknown setting {key}", "UNKNOWN_SETTING")
    t = spec[1]
    ok = {"string": lambda v: v is None or isinstance(v, str), "bool": lambda v: isinstance(v, bool),
          "int": lambda v: isinstance(v, int) and not isinstance(v, bool), "list": lambda v: isinstance(v, list),
          "json": lambda v: isinstance(v, dict)}[t](value)
    if not ok:
        raise Invalid(f"Setting {key} must be of type {t}", "INVALID_SETTING")
