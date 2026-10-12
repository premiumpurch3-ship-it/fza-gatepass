"""Runtime for form snapshots: maps API values <-> typed columns/custom_data and validates against a *pinned* snapshot."""
import re
from datetime import date, datetime, time as dtime
from decimal import Decimal, InvalidOperation

from ..core.db import rows

HEADER_CORE = {"reference_no", "vehicle_no", "seal_no", "planned_datetime", "location_id", "department_id", "responsible",
               "purpose_value", "category_value", "received_by_name", "inward_kind", "expected_return_date", "remarks"}
ITEM_CORE = {"description", "item_code", "quantity", "unit_id", "cartons", "pieces", "is_returnable", "remarks", "condition_value"}
ATTACH_CORE = {"attachments_photos", "attachments_files"}


def fields_of(snapshot: dict, scope: str, active_only=True):
    out = []
    for s in sorted(snapshot["sections"], key=lambda s: s["order"]):
        for f in sorted(s["fields"], key=lambda f: f["order"]):
            if f["scope"] == scope and (f["active"] or not active_only):
                out.append(f)
    return out


def _bad(errs, key, label, msg):
    errs.append({"field": key, "label": label, "message": msg})


def _coerce(f, v, errs):
    t, k, lbl = f["type"], f["key"], f["label"]
    val = f.get("validation") or {}
    if v is None or v == "":
        return None
    try:
        if t in ("TEXT", "LONGTEXT"):
            if not isinstance(v, str):
                raise ValueError
            v = v.strip()
            mx = val.get("max_length", 2000 if t == "LONGTEXT" else 300)
            if len(v) > mx:
                return _bad(errs, k, lbl, f"Must be at most {mx} characters")
            if val.get("regex") and not re.fullmatch(val["regex"], v):
                return _bad(errs, k, lbl, val.get("regex_message") or "Invalid format")
            if val.get("min_length") and len(v) < val["min_length"]:
                return _bad(errs, k, lbl, f"Must be at least {val['min_length']} characters")
            return v
        if t == "INTEGER":
            if isinstance(v, bool) or (isinstance(v, str) and not re.fullmatch(r"-?\d+", v.strip())) or (isinstance(v, float) and v != int(v)):
                raise ValueError
            n = int(v)
        elif t == "DECIMAL":
            if isinstance(v, bool):
                raise ValueError
            d = Decimal(str(v).strip())
            places = val.get("decimals", 3)
            if d.as_tuple().exponent < -places:
                return _bad(errs, k, lbl, f"At most {places} decimal places")
            n = d
        if t in ("INTEGER", "DECIMAL"):
            if "min" in val and n < val["min"]:
                return _bad(errs, k, lbl, f"Must be at least {val['min']}")
            if "max" in val and n > val["max"]:
                return _bad(errs, k, lbl, f"Must be at most {val['max']}")
            return n
        if t == "DATE":
            return date.fromisoformat(str(v)[:10])
        if t == "TIME":
            return dtime.fromisoformat(str(v)).strftime("%H:%M")
        if t == "DATETIME":
            d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            if d.tzinfo is None:
                return _bad(errs, k, lbl, "Date/time must include a timezone offset")
            return d
        if t == "YESNO":
            if not isinstance(v, bool):
                raise ValueError
            return v
        if t == "MULTISELECT":
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError
            return v
        if t in ("DROPDOWN", "LOCATION", "USER"):
            return v
    except (ValueError, InvalidOperation, TypeError):
        return _bad(errs, k, lbl, "Invalid value")
    return v


def _options_ok(c, f, v) -> bool:
    src = f.get("options") or {}
    s = src.get("source")
    vals = v if isinstance(v, list) else [v]
    if s == "INLINE":
        allowed = {o["value"] for o in src["items"] if o.get("active", True)}
        return all(x in allowed for x in vals)
    if s == "LOOKUP":
        allowed = {r["value"] for r in rows(c, "SELECT o.value FROM lookup_options o JOIN lookup_lists l ON l.id = o.list_id WHERE l.code = :c AND o.is_active", c=src["list"])}
        return all(x in allowed for x in vals)
    table = {"MASTER_LOCATIONS": "locations", "MASTER_DEPARTMENTS": "departments", "MASTER_UNITS": "units_of_measure"}.get(s)
    if table:
        ids = {str(r["id"]) for r in rows(c, f"SELECT id FROM {table} WHERE is_active AND id = ANY(CAST(:ids AS uuid[]))", ids=[str(x) for x in vals])}
        return all(str(x) in ids for x in vals)
    return True


def _visible(f, values) -> bool:
    r = f.get("visibility_rule")
    if not r:
        return True
    return values.get(r["field"]) == r.get("eq")


def validate_scope(c, snapshot, scope: str, values: dict, strict: bool):
    """Returns (clean, errors). Unknown keys are rejected. strict=True enforces required fields (submit)."""
    errs, clean = [], {}
    fields = {f["key"]: f for f in fields_of(snapshot, scope)}
    for k in values:
        if k not in fields:
            errs.append({"field": k, "label": k, "message": "Unknown or disabled field"})
    for k, f in fields.items():
        v = values.get(k)
        if f["type"] in ("ATTACHMENT", "IMAGE", "CAMERA"):
            continue
        if f["type"] == "USER":
            cv = None
            if isinstance(v, dict) and (v.get("user_id") or (v.get("name") or "").strip()):
                if v.get("user_id") and (v.get("name") or "").strip():
                    _bad(errs, k, f["label"], "Provide either a system user or a name, not both")
                elif v.get("user_id"):
                    if not rows(c, "SELECT 1 FROM users WHERE id = CAST(:u AS uuid) AND is_active", u=v["user_id"]):
                        _bad(errs, k, f["label"], "Selected user does not exist or is inactive")
                    cv = {"user_id": v["user_id"], "name": None}
                else:
                    cv = {"user_id": None, "name": v["name"].strip()[:120]}
            elif v not in (None, "", {}):
                _bad(errs, k, f["label"], "Invalid value")
            if cv is None and strict and f["required"] and _visible(f, values):
                _bad(errs, k, f["label"], "This field is required")
            clean[k] = cv
            continue
        cv = _coerce(f, v, errs)
        if cv is not None and f["type"] in ("DROPDOWN", "MULTISELECT", "LOCATION"):
            if f["type"] == "LOCATION":
                f = {**f, "options": {"source": "MASTER_LOCATIONS"}}
            if not _options_ok(c, f, cv):
                _bad(errs, k, f["label"], "Selected option is not available")
        if cv is None and v in (None, "") and f.get("default") is not None and not strict:
            pass
        if cv is None and strict and f["required"] and _visible(f, values):
            _bad(errs, k, f["label"], "This field is required")
        clean[k] = cv
    clean = {k: v for k, v in clean.items() if k in values}   # partial updates only touch the keys that were sent
    return clean, errs


def split_header(snapshot, clean: dict):
    """clean values -> (core columns dict, custom_data dict)."""
    core, custom = {}, {}
    for f in fields_of(snapshot, "HEADER"):
        if f["key"] not in clean or f["type"] in ("ATTACHMENT", "IMAGE", "CAMERA"):
            continue
        v = clean[f["key"]]
        if f["storage"] == "CUSTOM":
            custom[f["key"]] = _json(v)
        elif f["core"] == "responsible":
            core["responsible_user_id"] = (v or {}).get("user_id")
            core["responsible_name"] = (v or {}).get("name")
        else:
            col = {"purpose_value": "purpose_value", "category_value": "category_value"}.get(f["core"], f["core"])
            core[col] = v
    return core, custom


def split_item(snapshot, clean: dict):
    core, custom = {}, {}
    for f in fields_of(snapshot, "ITEM"):
        if f["key"] not in clean:
            continue
        v = clean[f["key"]]
        if f["storage"] == "CUSTOM":
            custom[f["key"]] = _json(v)
        else:
            core[f["core"]] = v
    return core, custom


def _json(v):
    if isinstance(v, (date, datetime)):
        return v.isoformat()
    if isinstance(v, Decimal):
        return str(v)
    return v


def header_values(snapshot, row: dict) -> dict:
    out = {}
    cd = row.get("custom_data") or {}
    for f in fields_of(snapshot, "HEADER", active_only=False):
        if f["storage"] == "CUSTOM":
            out[f["key"]] = cd.get(f["key"])
        elif f["core"] == "responsible":
            out[f["key"]] = ({"user_id": str(row["responsible_user_id"]) if row.get("responsible_user_id") else None, "name": row.get("responsible_name")}
                             if (row.get("responsible_user_id") or row.get("responsible_name")) else None)
        elif f["core"] in HEADER_CORE:
            v = row.get(f["core"])
            out[f["key"]] = _json(v) if not isinstance(v, str) and v is not None and f["type"] not in ("LOCATION", "DROPDOWN") else (str(v) if v is not None and f["type"] in ("LOCATION", "DROPDOWN") else v)
    return out


def item_values(snapshot, row: dict) -> dict:
    out = {}
    cd = row.get("custom_data") or {}
    for f in fields_of(snapshot, "ITEM", active_only=False):
        if f["storage"] == "CUSTOM":
            out[f["key"]] = cd.get(f["key"])
        else:
            v = row.get(f["core"])
            out[f["key"]] = str(v) if f["core"] in ("quantity", "unit_id") and v is not None else v
    return out
