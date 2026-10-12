"""Seed content for Form v1 of OUTWARD and INWARD (paper-form fidelity per D-26, plus approved application-level fields)."""
from ..core.db import J, one, q, rows

# key, label, type, storage, core_column, scope, section, required, locked, validation, options_source, lookup, flags
def F(key, label, type_, storage, core, scope, section, order, required=False, locked=False, validation=None, src="NONE", lookup=None,
      placeholder=None, help_=None, inline=None, list_=False, pdf=True, search=False, ui=None, rule=None, default=None):
    return dict(key=key, label=label, type=type_, storage=storage, core=core, scope=scope, section=section, order=order, required=required,
                locked=locked, validation=validation or {}, src=src, lookup=lookup, placeholder=placeholder, help=help_, inline=inline,
                list=list_, pdf=pdf, search=search, ui=ui or {}, rule=rule, default=default)


def header(kind: str):
    out = kind == "OUTWARD"
    f = [
        F("reference_no", "Reference #", "TEXT", "CORE", "reference_no", "HEADER", "header", 10, validation={"max_length": 50}, list_=True, search=True, ui={"width": 6}),
        F("location_id", "To Location" if out else "From Location", "LOCATION", "CORE", "location_id", "HEADER", "header", 20, required=True, list_=True, ui={"width": 6}),
        F("vehicle_no", "Vehicle #", "TEXT", "CORE", "vehicle_no", "HEADER", "header", 30, validation={"max_length": 20}, list_=True, search=True, placeholder="e.g. ABC-123", ui={"width": 6}),
        F("seal_no", "Seal #", "TEXT", "CORE", "seal_no", "HEADER", "header", 40, validation={"max_length": 30}, search=True, ui={"width": 6}),
        F("planned_datetime", "Time Out" if out else "Time In", "DATETIME", "CORE", "planned_datetime", "HEADER", "header", 50,
          help_="Planned time. The actual time is stamped by Security at the gate.", ui={"width": 6}),
        F("responsible", "Person / Employee Responsible", "USER", "CORE", "responsible", "HEADER", "header", 60, required=True, list_=True, ui={"width": 6},
          help_="Pick a system user or type an external person's name."),
        F("department_id", "Department", "DROPDOWN", "CORE", "department_id", "HEADER", "header", 70, src="MASTER_DEPARTMENTS", ui={"width": 6}),
        F("purpose_value", "Purpose", "DROPDOWN", "CORE", "purpose_value", "HEADER", "header", 80, src="LOOKUP", lookup="PURPOSE", ui={"width": 6}),
    ]
    if out:
        f += [F("category_value", "Category", "DROPDOWN", "CORE", "category_value", "HEADER", "header", 90, src="LOOKUP", lookup="GP_CATEGORY", ui={"width": 6}),
              F("expected_return_date", "Return Due Date", "DATE", "CORE", "expected_return_date", "HEADER", "header", 100, ui={"width": 6},
                help_="Required when any item is returnable.", list_=True)]
    else:
        f += [F("inward_kind", "Inward Type", "DROPDOWN", "CORE", "inward_kind", "HEADER", "header", 90, required=True, src="INLINE", ui={"width": 6},
                inline=[("RETURN_AGAINST_OUTWARD", "Return against Outward"), ("FRESH_INWARD", "Fresh inward (no original outward)")], default="RETURN_AGAINST_OUTWARD")]
    f += [F("received_by_name", "Received By", "TEXT", "CORE", "received_by_name", "HEADER", "header", 110, validation={"max_length": 120}, ui={"width": 6}),
          F("remarks", "Remarks", "LONGTEXT", "CORE", "remarks", "HEADER", "header", 120, validation={"max_length": 2000}, ui={"width": 12})]
    return f


def items(kind: str):
    f = [
        F("item_description", "Description", "TEXT", "SYSTEM", "description", "ITEM", "items", 10, required=True, locked=True, validation={"max_length": 300}),
        F("item_code", "Item / Product Code", "TEXT", "CORE", "item_code", "ITEM", "items", 20, validation={"max_length": 50}),
        F("quantity", "Quantity", "DECIMAL", "SYSTEM", "quantity", "ITEM", "items", 30, required=True, locked=True, validation={"min": 0.001, "decimals": 3}),
        F("unit_id", "Unit", "DROPDOWN", "SYSTEM", "unit_id", "ITEM", "items", 40, required=True, locked=True, src="MASTER_UNITS"),
        F("cartons", "No. of Cartons", "INTEGER", "CORE", "cartons", "ITEM", "items", 50, validation={"min": 0}),
        F("pieces", "No. of Pieces", "INTEGER", "CORE", "pieces", "ITEM", "items", 60, validation={"min": 0}),
        F("is_returnable", "Returnable", "YESNO", "SYSTEM", "is_returnable", "ITEM", "items", 70, required=True, locked=True),
        F("item_remarks", "Remarks", "TEXT", "CORE", "remarks", "ITEM", "items", 80, validation={"max_length": 300}),
    ]
    if kind == "INWARD":
        f.append(F("condition_value", "Condition", "DROPDOWN", "CORE", "condition_value", "ITEM", "items", 75, src="LOOKUP", lookup="ITEM_CONDITION"))
    return f


def evidence():
    return [F("photos", "Product / Material Photos", "CAMERA", "SYSTEM", "attachments_photos", "HEADER", "evidence", 10, locked=True, required=False,
              help_="Camera capture or upload."),
            F("attachments", "Attachments", "ATTACHMENT", "SYSTEM", "attachments_files", "HEADER", "evidence", 20, locked=True)]


SECTIONS = [("header", "Gate Pass Details", "HEADER", 10), ("items", "Items", "ITEM", 20), ("evidence", "Evidence & Attachments", "EVIDENCE", 30)]


def seed_reference_data(c):
    for code, name, dp in [("PCS", "Pieces", 0), ("CTN", "Cartons", 0), ("SET", "Sets", 0), ("PAIR", "Pairs", 0), ("BOX", "Boxes", 0),
                           ("ROLL", "Rolls", 0), ("DOZ", "Dozens", 0), ("KG", "Kilograms", 3), ("MTR", "Meters", 2), ("LTR", "Litres", 3)]:
        q(c, "INSERT INTO units_of_measure (code, name, decimal_places) VALUES (:c, :n, :d) ON CONFLICT (code) DO NOTHING", c=code, n=name, d=dp)
    lists = {"PURPOSE": ("Purpose", [("REPAIR", "Repair"), ("SAMPLE_APPROVAL", "Sample approval"), ("EXHIBITION", "Exhibition"), ("TESTING", "Testing"),
                                      ("CUSTOMER_DEMO", "Customer demo"), ("OTHER", "Other")]),
             "GP_CATEGORY": ("Gate Pass Category", [("SAMPLE", "Sample"), ("REPAIR_SERVICE", "Repair / Service"), ("EXHIBITION_EVENT", "Exhibition / Event"),
                                                    ("LOAN_TRIAL", "Loan / Trial"), ("OTHER", "Other")]),
             "ITEM_CONDITION": ("Item Condition", [("GOOD", "Good"), ("DAMAGED", "Damaged"), ("INCOMPLETE", "Incomplete"), ("UNUSABLE", "Unusable")])}
    for code, (name, opts) in lists.items():
        r = one(c, "INSERT INTO lookup_lists (code, name, is_system) VALUES (:c, :n, true) ON CONFLICT (code) DO UPDATE SET name = :n RETURNING id", c=code, n=name)
        for i, (v, l) in enumerate(opts):
            q(c, "INSERT INTO lookup_options (list_id, value, label, sort_order) VALUES (:l, :v, :lb, :s) ON CONFLICT DO NOTHING", l=r["id"], v=v, lb=l, s=i * 10)
    loc = one(c, """INSERT INTO locations (code, name, location_type) VALUES ('MAIN', 'MTJ-Clothing Main Premises', 'INTERNAL')
                    ON CONFLICT (code) DO UPDATE SET name = locations.name RETURNING id""")
    q(c, "INSERT INTO gates (code, name, location_id) VALUES ('GATE-1', 'Main Security Gate', :l) ON CONFLICT (code) DO NOTHING", l=loc["id"])
    for code, name, direction, levels, mn in [("OUTWARD", "Outward Gate Pass", "OUT", 2, 1), ("INWARD", "Inward Gate Pass", "IN", 1, 0)]:
        q(c, """INSERT INTO gate_pass_types (code, name, direction, approval_levels, min_photos, sort_order) VALUES (:c, :n, :d, :l, :m, :s)
                ON CONFLICT (code) DO NOTHING""", c=code, n=name, d=direction, l=levels, m=mn, s=0 if direction == "OUT" else 1)


def seed_forms(c):
    """Create form v1 (PUBLISHED) for each type if no definition exists. Uses the same service code as the admin builder."""
    from . import forms
    for code in ("OUTWARD", "INWARD"):
        t = one(c, "SELECT id FROM gate_pass_types WHERE code = :c", c=code)
        if one(c, "SELECT 1 AS x FROM form_definitions WHERE gate_pass_type_id = :t", t=t["id"]):
            continue
        fd = one(c, "INSERT INTO form_definitions (gate_pass_type_id, name) VALUES (:t, :n) RETURNING id", t=t["id"], n=f"{code.title()} Gate Pass Form")
        v = one(c, "INSERT INTO form_versions (form_definition_id, version_no, status, created_by) VALUES (:f, 1, 'DRAFT', NULL) RETURNING id", f=fd["id"])
        secs = {}
        for key, title, scope, order in SECTIONS:
            secs[key] = one(c, "INSERT INTO form_sections (form_version_id, section_key, title, scope, display_order) VALUES (:v, :k, :t, :s, :o) RETURNING id",
                            v=v["id"], k=key, t=title, s=scope, o=order)["id"]
        for f in header(code) + items(code) + evidence():
            forms._insert_field(c, v["id"], secs[f["section"]], f, actor_id=None)
        forms._publish_version(c, fd["id"], v["id"], None, "Initial form (paper-form baseline)", stamp_registry=True)
