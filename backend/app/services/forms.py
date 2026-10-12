"""Dynamic form builder: drafts, edits, validation, publish (immutable versions), snapshots."""
import hashlib
import json
import re

from ..core import settings_store as ss
from ..core.audit import audit
from ..core.db import J, one, q, rows, scalar, tx
from ..core.errors import Conflict, Forbidden, Invalid, NotFound

FIELD_TYPES = ["TEXT", "LONGTEXT", "INTEGER", "DECIMAL", "DATE", "TIME", "DATETIME", "YESNO", "DROPDOWN", "MULTISELECT",
               "USER", "LOCATION", "ATTACHMENT", "IMAGE", "CAMERA"]
KEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,48}$")
VAL_RE = re.compile(r"^[A-Z0-9_]{1,40}$")


# ---------- low level ----------
def _insert_field(c, version_id, section_id, f: dict, actor_id):
    """f uses the seed spec shape. Registers the key if new."""
    reg = one(c, "SELECT * FROM form_field_registry WHERE field_key = :k", k=f["key"])
    if reg is None:
        q(c, "INSERT INTO form_field_registry (field_key, field_type, storage_class, core_column, created_by) VALUES (:k, :t, :s, :c, :u)",
          k=f["key"], t=f["type"], s=f["storage"], c=f["core"], u=actor_id)
    elif (reg["field_type"], reg["storage_class"], reg["core_column"]) != (f["type"], f["storage"], f["core"]):
        raise Conflict("FIELD_KEY_IN_USE", f"Field key '{f['key']}' already exists with a different type or storage")
    lookup_id = scalar(c, "SELECT id FROM lookup_lists WHERE code = :c", c=f["lookup"]) if f.get("lookup") else None
    fid = one(c, """INSERT INTO form_fields (form_version_id, section_id, field_key, scope, label, field_type, storage_class, core_column, is_required,
                      is_locked, display_order, default_value, placeholder, help_text, validation, options_source, lookup_list_id,
                      visibility_rule, show_in_list, show_in_pdf, is_searchable, ui)
                    VALUES (:v, :s, :k, :sc, :l, :t, :st, :cc, :r, :lk, :o, CAST(:d AS jsonb), :ph, :h, CAST(:val AS jsonb), :src, :li,
                      CAST(:rule AS jsonb), :sl, :sp, :se, CAST(:ui AS jsonb)) RETURNING id""",
              v=version_id, s=section_id, k=f["key"], sc=f["scope"], l=f["label"], t=f["type"], st=f["storage"], cc=f["core"], r=f.get("required", False),
              lk=f.get("locked", False), o=f["order"], d=J(f.get("default")), ph=f.get("placeholder"), h=f.get("help"), val=J(f.get("validation") or {}),
              src=f.get("src", "NONE"), li=lookup_id, rule=J(f.get("rule")), sl=f.get("list", False), sp=f.get("pdf", True), se=f.get("search", False),
              ui=J(f.get("ui") or {}))["id"]
    for i, (v, l) in enumerate(f.get("inline") or []):
        q(c, "INSERT INTO form_field_options (form_field_id, value, label, sort_order, is_default) VALUES (:f, :v, :l, :s, :d)",
          f=fid, v=v, l=l, s=i * 10, d=(f.get("default") == v))
    return fid


def build_snapshot(c, version_id) -> dict:
    ver = one(c, """SELECT v.version_no, t.code AS type_code, t.approval_levels, t.min_photos, t.max_photos FROM form_versions v
                    JOIN form_definitions d ON d.id = v.form_definition_id JOIN gate_pass_types t ON t.id = d.gate_pass_type_id WHERE v.id = :v""", v=version_id)
    secs = rows(c, "SELECT id, section_key, title, scope, display_order FROM form_sections WHERE form_version_id = :v ORDER BY display_order", v=version_id)
    out = {"version": ver["version_no"], "gate_pass_type": ver["type_code"], "sections": [],
           "rules": {"approval_levels": ver["approval_levels"], "min_photos": ver["min_photos"], "max_photos": ver["max_photos"]}}
    for s in secs:
        fields = []
        for f in rows(c, """SELECT f.*, l.code AS lookup_code FROM form_fields f LEFT JOIN lookup_lists l ON l.id = f.lookup_list_id
                            WHERE f.section_id = :s ORDER BY f.display_order, f.field_key""", s=s["id"]):
            opts = None
            if f["options_source"] == "INLINE":
                opts = {"source": "INLINE", "items": [{"value": o["value"], "label": o["label"], "active": o["is_active"], "default": o["is_default"]}
                                                      for o in rows(c, "SELECT * FROM form_field_options WHERE form_field_id = :f ORDER BY sort_order, value", f=f["id"])]}
            elif f["options_source"] == "LOOKUP":
                opts = {"source": "LOOKUP", "list": f["lookup_code"]}
            elif f["options_source"] != "NONE":
                opts = {"source": f["options_source"]}
            fields.append({"key": f["field_key"], "label": f["label"], "type": f["field_type"], "scope": f["scope"], "storage": f["storage_class"],
                           "core": f["core_column"], "required": f["is_required"], "active": f["is_active"], "locked": f["is_locked"],
                           "order": f["display_order"], "default": f["default_value"], "placeholder": f["placeholder"], "help": f["help_text"],
                           "validation": f["validation"], "options": opts, "visibility_rule": f["visibility_rule"],
                           "flags": {"list": f["show_in_list"], "pdf": f["show_in_pdf"], "search": f["is_searchable"]}, "ui": f["ui"]})
        out["sections"].append({"key": s["section_key"], "title": s["title"], "scope": s["scope"], "order": s["display_order"], "fields": fields})
    return out


def _hash(snap) -> str:
    return hashlib.sha256(json.dumps(snap, sort_keys=True, default=str).encode()).hexdigest()


def _publish_version(c, definition_id, draft_id, actor_id, note, stamp_registry=True):
    snap = build_snapshot(c, draft_id)
    cur = one(c, "SELECT id FROM form_versions WHERE form_definition_id = :d AND status = 'PUBLISHED'", d=definition_id)
    prev_keys = set()
    if cur:
        prev_keys = {r["field_key"] for r in rows(c, "SELECT field_key FROM form_fields WHERE form_version_id = :v AND is_active", v=cur["id"])}
        q(c, "UPDATE form_versions SET status = 'ARCHIVED', archived_at = now() WHERE id = :v", v=cur["id"])   # archive first (one-published index)
    q(c, """UPDATE form_versions SET status = 'PUBLISHED', snapshot = CAST(:s AS jsonb), schema_hash = :h, published_by = :u, published_at = now(),
            change_note = :n WHERE id = :v""", s=J(snap), h=_hash(snap), u=actor_id, n=note, v=draft_id)
    q(c, "UPDATE form_definitions SET current_version_id = :v WHERE id = :d", v=draft_id, d=definition_id)
    new_keys = {r["field_key"] for r in rows(c, "SELECT field_key FROM form_fields WHERE form_version_id = :v AND is_active", v=draft_id)}
    q(c, "UPDATE form_field_registry SET first_published_at = COALESCE(first_published_at, now()) WHERE field_key IN (SELECT field_key FROM form_fields WHERE form_version_id = :v)", v=draft_id)
    if prev_keys - new_keys:
        q(c, "UPDATE form_field_registry SET retired_at = now() WHERE field_key = ANY(:k)", k=list(prev_keys - new_keys))
    if new_keys:
        q(c, "UPDATE form_field_registry SET retired_at = NULL WHERE field_key = ANY(:k)", k=list(new_keys))
    return snap


def _type(c, code):
    t = one(c, "SELECT t.id, t.code, d.id AS def_id, d.current_version_id FROM gate_pass_types t JOIN form_definitions d ON d.gate_pass_type_id = t.id WHERE t.code = :c", c=code.upper())
    if not t:
        raise NotFound("Gate pass type")
    return t


def _draft(c, code, create=False, actor=None):
    t = _type(c, code)
    d = one(c, "SELECT id FROM form_versions WHERE form_definition_id = :d AND status = 'DRAFT' FOR UPDATE", d=t["def_id"])
    if d or not create:
        return t, d
    return t, _create_draft_row(c, t, actor, None)


def _create_draft_row(c, t, actor, from_version_id):
    src = from_version_id or t["current_version_id"]
    nxt = scalar(c, "SELECT coalesce(max(version_no), 0) + 1 FROM form_versions WHERE form_definition_id = :d", d=t["def_id"])
    v = one(c, "INSERT INTO form_versions (form_definition_id, version_no, status, base_version_id, created_by) VALUES (:d, :n, 'DRAFT', :b, :u) RETURNING id",
            d=t["def_id"], n=nxt, b=src, u=actor["id"] if actor else None)
    smap = {}
    for s in rows(c, "SELECT * FROM form_sections WHERE form_version_id = :v", v=src):
        smap[s["id"]] = one(c, "INSERT INTO form_sections (form_version_id, section_key, title, scope, display_order, is_collapsible) VALUES (:v,:k,:t,:s,:o,:c) RETURNING id",
                            v=v["id"], k=s["section_key"], t=s["title"], s=s["scope"], o=s["display_order"], c=s["is_collapsible"])["id"]
    for f in rows(c, "SELECT * FROM form_fields WHERE form_version_id = :v", v=src):
        nid = one(c, """INSERT INTO form_fields (form_version_id, section_id, field_key, scope, label, field_type, storage_class, core_column, is_required, is_active,
                          is_locked, display_order, default_value, placeholder, help_text, validation, options_source, lookup_list_id, visibility_rule,
                          show_in_list, show_in_pdf, is_searchable, ui)
                        VALUES (:v,:s,:k,:sc,:l,:t,:st,:cc,:r,:a,:lk,:o,CAST(:d AS jsonb),:ph,:h,CAST(:val AS jsonb),:src,:li,CAST(:rule AS jsonb),:sl,:sp,:se,CAST(:ui AS jsonb))
                        RETURNING id""", v=v["id"], s=smap[f["section_id"]], k=f["field_key"], sc=f["scope"], l=f["label"], t=f["field_type"], st=f["storage_class"],
                  cc=f["core_column"], r=f["is_required"], a=f["is_active"], lk=f["is_locked"], o=f["display_order"], d=J(f["default_value"]), ph=f["placeholder"],
                  h=f["help_text"], val=J(f["validation"]), src=f["options_source"], li=f["lookup_list_id"], rule=J(f["visibility_rule"]),
                  sl=f["show_in_list"], sp=f["show_in_pdf"], se=f["is_searchable"], ui=J(f["ui"]))["id"]
        for o in rows(c, "SELECT * FROM form_field_options WHERE form_field_id = :f", f=f["id"]):
            q(c, "INSERT INTO form_field_options (form_field_id, value, label, sort_order, is_active, is_default) VALUES (:f,:v,:l,:s,:a,:d)",
              f=nid, v=o["value"], l=o["label"], s=o["sort_order"], a=o["is_active"], d=o["is_default"])
    return v


# ---------- read ----------
def published(code):
    with tx() as c:
        t = _type(c, code)
        v = one(c, "SELECT id, version_no, snapshot, schema_hash FROM form_versions WHERE id = :v", v=t["current_version_id"])
        return {"version_id": v["id"], "version_no": v["version_no"], "schema_hash": v["schema_hash"], "snapshot": v["snapshot"]}


def get_version(vid):
    with tx() as c:
        v = one(c, "SELECT id, version_no, status, snapshot, change_note, published_at FROM form_versions WHERE id = :v", v=vid)
        if not v:
            raise NotFound("Form version")
        if v["status"] == "DRAFT":
            v["snapshot"] = build_snapshot(c, vid)
        return v


def list_forms():
    with tx() as c:
        out = rows(c, """SELECT t.code, t.name, d.current_version_id,
                         (SELECT version_no FROM form_versions WHERE id = d.current_version_id) AS published_version,
                         (SELECT id FROM form_versions WHERE form_definition_id = d.id AND status = 'DRAFT') AS draft_id
                         FROM gate_pass_types t JOIN form_definitions d ON d.gate_pass_type_id = t.id ORDER BY t.sort_order""")
        return out


def versions(code):
    with tx() as c:
        t = _type(c, code)
        return rows(c, """SELECT v.id, v.version_no, v.status, v.change_note, v.published_at, u.full_name AS published_by,
                          (SELECT count(*) FROM gate_passes g WHERE g.form_version_id = v.id) AS gate_passes
                          FROM form_versions v LEFT JOIN users u ON u.id = v.published_by WHERE v.form_definition_id = :d ORDER BY v.version_no DESC""", d=t["def_id"])


def get_draft(code):
    with tx() as c:
        t, d = _draft(c, code)
        if not d:
            raise NotFound("Draft")
        return {"version_id": d["id"], "snapshot": build_snapshot(c, d["id"])}


# ---------- draft editing ----------
def create_draft(actor, code, from_version_id=None):
    with tx() as c:
        t, d = _draft(c, code)
        if d:
            raise Conflict("DRAFT_EXISTS", "A draft already exists for this form")
        v = _create_draft_row(c, t, actor, from_version_id)
        audit(c, "form.draft.create", "form_version", v["id"], f"Draft created for {code.upper()} form")
        return {"version_id": v["id"], "snapshot": build_snapshot(c, v["id"])}


def discard_draft(actor, code):
    with tx() as c:
        t, d = _draft(c, code)
        if not d:
            raise NotFound("Draft")
        q(c, "DELETE FROM form_versions WHERE id = :v", v=d["id"])
        audit(c, "form.draft.discard", "form_version", d["id"], f"Draft of {code.upper()} form discarded")


def _fld(c, version_id, key):
    f = one(c, "SELECT * FROM form_fields WHERE form_version_id = :v AND field_key = :k", v=version_id, k=key)
    if not f:
        raise NotFound(f"Field '{key}'")
    return f


def add_field(actor, spec: dict, applies_to: list[str]):
    key = spec["key"]
    if not KEY_RE.match(key):
        raise Invalid("Field key must be lowercase letters, digits and underscores (2-49 chars, starting with a letter)", "INVALID_KEY")
    if spec["type"] not in FIELD_TYPES:
        raise Invalid("Unsupported field type", "INVALID_TYPE")
    if spec["type"] == "DROPDOWN" and spec.get("src", "INLINE") == "NONE":
        raise Invalid("Dropdown needs an option source", "INVALID_OPTIONS")
    out = {}
    with tx() as c:
        for code in applies_to:
            t, d = _draft(c, code, create=True, actor=actor)
            if one(c, "SELECT 1 AS x FROM form_fields WHERE form_version_id = :v AND field_key = :k", v=d["id"], k=key):
                raise Conflict("DUPLICATE", f"Field '{key}' already exists in the {code} draft")
            scope = spec.get("scope", "HEADER")
            sec = one(c, "SELECT id FROM form_sections WHERE form_version_id = :v AND section_key = :s", v=d["id"], s=spec.get("section") or ("items" if scope == "ITEM" else "header"))
            if not sec:
                raise Invalid("Unknown section", "UNKNOWN_SECTION")
            mx = scalar(c, "SELECT coalesce(max(display_order), 0) FROM form_fields WHERE section_id = :s", s=sec["id"])
            storage = "CUSTOM"
            f = dict(key=key, label=spec["label"], type=spec["type"], storage=storage, core=None, scope=scope, order=spec.get("order", mx + 10),
                     required=spec.get("required", False), validation=spec.get("validation") or {}, src=spec.get("src", "NONE"), lookup=spec.get("lookup"),
                     placeholder=spec.get("placeholder"), help=spec.get("help"), default=spec.get("default"), list=spec.get("list", False),
                     pdf=spec.get("pdf", True), search=spec.get("search", False), ui=spec.get("ui") or {}, rule=spec.get("rule"),
                     inline=[(o["value"], o["label"]) for o in spec.get("options", [])])
            for v, _ in f["inline"]:
                if not VAL_RE.match(v):
                    raise Invalid("Option values must be UPPER_CASE letters, digits, underscore", "INVALID_OPTIONS")
            _insert_field(c, d["id"], sec["id"], f, actor["id"])
            audit(c, "form.field.add", "form_field", key, f"Field '{spec['label']}' added to {code} draft", after={"key": key, "type": spec["type"], "label": spec["label"]})
            out[code] = key
    return out


PATCHABLE = {"label", "is_required", "is_active", "display_order", "default_value", "placeholder", "help_text", "validation", "show_in_list",
             "show_in_pdf", "is_searchable", "ui", "visibility_rule"}


def patch_field(actor, code, key, patch: dict):
    with tx() as c:
        t, d = _draft(c, code)
        if not d:
            raise NotFound("Draft (create a draft first)")
        f = _fld(c, d["id"], key)
        if f["is_locked"] and (patch.get("is_active") is False or patch.get("is_required") is False):
            raise Forbidden("This is a system-locked field: it cannot be disabled or made optional", "FIELD_LOCKED")
        sets, params = [], {}
        for k, v in patch.items():
            if k in PATCHABLE:
                if k in ("validation", "ui", "default_value", "visibility_rule"):
                    sets.append(f"{k} = CAST(:{k} AS jsonb)"); params[k] = J(v)
                else:
                    sets.append(f"{k} = :{k}"); params[k] = v
        if "validation" in patch and patch["validation"].get("regex"):
            try:
                re.compile(patch["validation"]["regex"])
            except re.error:
                raise Invalid("Invalid regular expression", "INVALID_REGEX")
        if "type" in patch and patch["type"] != f["field_type"]:
            reg = one(c, "SELECT * FROM form_field_registry WHERE field_key = :k", k=key)
            if f["storage_class"] != "CUSTOM" or reg["first_published_at"] is not None:
                raise Forbidden("The type of a published (or system/core) field is frozen. Disable it and add a new field instead.", "TYPE_FROZEN")
            if patch["type"] not in FIELD_TYPES:
                raise Invalid("Unsupported field type", "INVALID_TYPE")
            q(c, "UPDATE form_field_registry SET field_type = :t WHERE field_key = :k", t=patch["type"], k=key)
            sets.append("field_type = :ft"); params["ft"] = patch["type"]
        if "section" in patch:
            sec = one(c, "SELECT id, scope FROM form_sections WHERE form_version_id = :v AND section_key = :s", v=d["id"], s=patch["section"])
            if not sec or sec["scope"] not in ("HEADER", "ITEM") or sec["scope"] != f["scope"]:
                raise Invalid("Invalid section for this field", "UNKNOWN_SECTION")
            sets.append("section_id = :sec"); params["sec"] = sec["id"]
        if "options_source" in patch:
            sets.append("options_source = :os"); params["os"] = patch["options_source"]
            lid = scalar(c, "SELECT id FROM lookup_lists WHERE code = :c", c=patch.get("lookup")) if patch.get("lookup") else None
            sets.append("lookup_list_id = :li"); params["li"] = lid
        if sets:
            q(c, f"UPDATE form_fields SET {', '.join(sets)} WHERE id = :id", id=f["id"], **params)
        audit(c, "form.field.disable" if patch.get("is_active") is False else "form.field.update", "form_field", key,
              f"Field '{key}' updated in {code.upper()} draft", before={k: f.get(k) for k in patch if k in f}, after=patch)
        return {k: v for k, v in _fld(c, d["id"], key).items() if k in ("field_key", "label", "is_required", "is_active", "display_order")}


def delete_field(actor, code, key):
    with tx() as c:
        t, d = _draft(c, code)
        if not d:
            raise NotFound("Draft")
        f = _fld(c, d["id"], key)
        reg = one(c, "SELECT * FROM form_field_registry WHERE field_key = :k", k=key)
        if f["storage_class"] != "CUSTOM" or reg["first_published_at"] is not None:
            raise Forbidden("Only unpublished custom fields can be deleted. Use Disable instead; historical records keep their data.", "DELETE_NOT_SAFE")
        q(c, "DELETE FROM form_fields WHERE id = :f", f=f["id"])
        if not scalar(c, "SELECT count(*) FROM form_fields WHERE field_key = :k", k=key):
            q(c, "DELETE FROM form_field_registry WHERE field_key = :k", k=key)
        audit(c, "form.field.delete", "form_field", key, f"Field '{key}' deleted from {code.upper()} draft")


def set_options(actor, code, key, options: list[dict]):
    with tx() as c:
        t, d = _draft(c, code)
        if not d:
            raise NotFound("Draft")
        f = _fld(c, d["id"], key)
        if f["field_type"] not in ("DROPDOWN", "MULTISELECT"):
            raise Invalid("Field is not a dropdown", "INVALID_OPTIONS")
        seen = set()
        for o in options:
            if not VAL_RE.match(o["value"]) or o["value"] in seen:
                raise Invalid("Option values must be unique UPPER_CASE codes", "INVALID_OPTIONS")
            seen.add(o["value"])
        q(c, "UPDATE form_fields SET options_source = 'INLINE', lookup_list_id = NULL WHERE id = :f", f=f["id"])
        q(c, "DELETE FROM form_field_options WHERE form_field_id = :f", f=f["id"])
        for i, o in enumerate(options):
            q(c, "INSERT INTO form_field_options (form_field_id, value, label, sort_order, is_active, is_default) VALUES (:f,:v,:l,:s,:a,:d)",
              f=f["id"], v=o["value"], l=o["label"], s=i * 10, a=o.get("active", True), d=o.get("default", False))
        audit(c, "form.field.update", "form_field", key, f"Options of '{key}' replaced in {code.upper()} draft", after={"options": [o["value"] for o in options]})


def reorder(actor, code, order: list[str]):
    with tx() as c:
        t, d = _draft(c, code)
        if not d:
            raise NotFound("Draft")
        for i, key in enumerate(order):
            _fld(c, d["id"], key)
            q(c, "UPDATE form_fields SET display_order = :o WHERE form_version_id = :v AND field_key = :k", o=(i + 1) * 10, v=d["id"], k=key)
        audit(c, "form.field.reorder", "form_version", d["id"], f"Fields reordered in {code.upper()} draft", after={"order": order})


# ---------- validate / diff / publish ----------
def _problems(c, code, vid) -> list[str]:
    snap = build_snapshot(c, vid)
    p = []
    fields = [f for s in snap["sections"] for f in s["fields"]]
    by = {f["key"]: f for f in fields}
    for k in ("item_description", "quantity", "unit_id", "is_returnable"):
        if k not in by or not by[k]["active"] or (k != "is_returnable" and not by[k]["required"]):
            p.append(f"Locked item field '{k}' must be present, active and required")
    for k in (ss.get("forms.mandatory_fields", c) or []):
        if k not in by or not by[k]["active"] or not by[k]["required"]:
            p.append(f"Field '{k}' must remain active and required (mandatory by policy)")
    if code.upper() == "OUTWARD" and ("expected_return_date" not in by or not by["expected_return_date"]["active"]):
        p.append("Outward form must keep the Return Due Date field (returnable tracking)")
    for f in fields:
        if f["type"] in ("DROPDOWN", "MULTISELECT"):
            o = f["options"]
            if not o:
                p.append(f"'{f['label']}' has no option source")
            elif o["source"] == "INLINE" and not any(i["active"] for i in o["items"]):
                p.append(f"'{f['label']}' needs at least one active option")
        rx = (f["validation"] or {}).get("regex")
        if rx:
            try:
                re.compile(rx)
            except re.error:
                p.append(f"'{f['label']}' has an invalid regular expression")
        r = f.get("visibility_rule")
        if r and r.get("field") not in by:
            p.append(f"'{f['label']}' visibility rule references an unknown field")
    return p


def validate_draft(code):
    with tx() as c:
        t, d = _draft(c, code)
        if not d:
            raise NotFound("Draft")
        pr = _problems(c, code, d["id"])
        return {"ok": not pr, "problems": pr}


def _flat(snap):
    return {f["key"]: f for s in snap["sections"] for f in s["fields"]}


def diff_draft(code):
    with tx() as c:
        t, d = _draft(c, code)
        if not d:
            raise NotFound("Draft")
        new = _flat(build_snapshot(c, d["id"]))
        old = _flat(one(c, "SELECT snapshot FROM form_versions WHERE id = :v", v=t["current_version_id"])["snapshot"])
        out = {"added": sorted(set(new) - set(old)), "removed": sorted(set(old) - set(new)), "changed": [], "disabled": [], "enabled": []}
        for k in set(new) & set(old):
            a, b = old[k], new[k]
            if a["active"] and not b["active"]:
                out["disabled"].append(k)
            elif not a["active"] and b["active"]:
                out["enabled"].append(k)
            ch = [x for x in ("label", "required", "order", "validation", "placeholder", "help", "default", "options") if a.get(x) != b.get(x)]
            if ch:
                out["changed"].append({"key": k, "what": ch})
        return out


def publish(actor, codes: list[str], note: str):
    if not note or not note.strip():
        raise Invalid("A change note is required to publish", "NOTE_REQUIRED")
    result = {}
    with tx() as c:
        for code in codes:
            t, d = _draft(c, code)
            if not d:
                raise NotFound(f"Draft for {code}")
            pr = _problems(c, code, d["id"])
            if pr:
                raise Invalid("The draft cannot be published", "PUBLISH_BLOCKED", problems=pr)
        for code in codes:
            t, d = _draft(c, code)
            snap = _publish_version(c, t["def_id"], d["id"], actor["id"], note.strip())
            audit(c, "form.publish", "form_version", d["id"], f"{code.upper()} form v{snap['version']} published: {note.strip()}",
                  after={"version": snap["version"], "fields": len(_flat(snap)), "note": note.strip()})
            result[code.upper()] = snap["version"]
    return result
