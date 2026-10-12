import io
import re
import zipfile

import pytest
from PIL import Image

from tests.conftest import header, item, jpeg_bytes, new_outward, submitted_approved_outward, upload
from app.core.db import one, q, rows, tx


# ---------------- attachments ----------------
def test_photo_upload_download_and_thumbnail(world):
    w = world
    gp = new_outward(w, with_photo=False)
    aid, r = upload(w.creator, gp["id"], jpeg_bytes((300, 200)), "evidence.jpg")
    assert r.json()["status"] == "READY" and r.json()["width"] == 300 and r.json()["has_thumbnail"]
    d = w.creator.get(f"/gate-passes/{gp['id']}").json()
    assert d["attachments"][0]["detected_mime"] == "image/jpeg" and d["attachments"][0]["uploaded_by_name"]
    dl = w.creator.get(f"/attachments/{aid}/download").json()
    got = w.creator.client.get(dl["url"].replace("http://testserver", ""))
    assert got.status_code == 200 and got.content[:3] == b"\xff\xd8\xff"
    th = w.creator.get(f"/attachments/{aid}/thumbnail").json()
    assert w.creator.client.get(th["url"].replace("http://testserver", "")).status_code == 200
    # another creator cannot access it; an unauthenticated link with a tampered token fails
    assert w.creator2.get(f"/attachments/{aid}/download").status_code == 404
    assert w.creator.client.get("/api/v1/storage/local/not-a-token").status_code == 403
    # download is audited
    assert w.master.get("/audit-logs", params={"action": "attachment.download"}).json()["total"] == 1


def test_server_side_validation_rejects_spoofed_and_disallowed_files(world):
    w = world
    gp = new_outward(w, with_photo=False)
    # extension says jpg but content is a PDF/ text => rejected by magic bytes
    aid, r = upload(w.creator, gp["id"], b"%PDF-1.4 fake pdf content", "photo.jpg", expect_confirm=422)
    assert r.json()["code"] == "FILE_TYPE_MISMATCH"
    aid, r = upload(w.creator, gp["id"], b"MZ\x90\x00 this is an exe", "invoice.pdf", expect_confirm=422)
    assert r.json()["code"] == "FILE_TYPE_MISMATCH"
    # disallowed extensions are refused at registration
    for bad in ("run.exe", "page.html", "image.svg", "x.js", "archive.zip", "noext"):
        rr = w.creator.post(f"/gate-passes/{gp['id']}/attachments", {"filename": bad, "size": 100})
        assert rr.status_code == 422 and rr.json()["code"] == "FILE_TYPE_NOT_ALLOWED", bad
    # size limit
    rr = w.creator.post(f"/gate-passes/{gp['id']}/attachments", {"filename": "big.jpg", "size": 16 * 1024 * 1024})
    assert rr.status_code == 422 and rr.json()["code"] == "FILE_TOO_LARGE"
    # quarantined files are not downloadable and block submission
    with tx() as c:
        assert one(c, "SELECT count(*) AS n FROM gate_pass_attachments WHERE status = 'QUARANTINED'")["n"] == 2
    assert w.master.get("/audit-logs", params={"action": "attachment.quarantine"}).json()["total"] == 2


def test_pdf_docx_video_and_heic_handling(world):
    w = world
    gp = new_outward(w, with_photo=False)
    pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
    _, r = upload(w.creator, gp["id"], pdf, "invoice.pdf")
    assert r.json()["detected_mime"] == "application/pdf"
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("[Content_Types].xml", "<x/>"); z.writestr("word/document.xml", "<w/>")
    _, r = upload(w.creator, gp["id"], b.getvalue(), "note.docx")
    assert r.json()["status"] == "READY"
    fake = io.BytesIO()
    with zipfile.ZipFile(fake, "w") as z:
        z.writestr("hello.txt", "hi")
    upload(w.creator, gp["id"], fake.getvalue(), "fake.docx", expect_confirm=422)               # a zip pretending to be Word
    mp4 = bytes.fromhex("0000001866747970697373306d3469736f6d") + b"\x00" * 64                  # minimal ftyp box
    _, r = upload(w.creator, gp["id"], b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + b"\x00" * 200, "clip.mp4")
    assert r.json()["kind"] == "VIDEO" and r.json()["status"] == "READY"
    with tx() as c:                                                                               # video hash is computed by the worker job
        assert one(c, "SELECT count(*) AS n FROM background_jobs WHERE job_type = 'attachment.hash'")["n"] == 1
    from app import worker
    assert worker.process_jobs() == 1
    with tx() as c:
        assert one(c, "SELECT sha256 FROM gate_pass_attachments WHERE original_filename = 'clip.mp4'")["sha256"]
    # HEIC -> JPEG conversion (D-15)
    import pillow_heif
    pillow_heif.register_heif_opener()
    h = io.BytesIO()
    try:
        Image.new("RGB", (40, 30), (10, 120, 200)).save(h, "HEIF")
    except Exception:
        pytest.skip("HEIF encoder unavailable")
    aid, r = upload(w.creator, gp["id"], h.getvalue(), "IMG_0001.HEIC", captured=False)
    assert r.json()["detected_mime"] == "image/jpeg" and r.json()["original_filename"].endswith(".jpg")


def test_exif_gps_is_stripped(world):
    w = world
    gp = new_outward(w, with_photo=False)
    im = Image.new("RGB", (50, 50), "red")
    exif = Image.Exif()
    exif[0x8825] = {1: "N", 2: (24.0, 51.0, 0.0)}      # GPS IFD
    b = io.BytesIO(); im.save(b, "JPEG", exif=exif)
    aid, r = upload(w.creator, gp["id"], b.getvalue(), "gps.jpg")
    from app.storage import get_storage
    with tx() as c:
        key = one(c, "SELECT storage_key FROM gate_pass_attachments WHERE id = :i", i=aid)["storage_key"]
    stored = Image.open(io.BytesIO(get_storage().read_all(key)))
    assert not stored.getexif().get(0x8825)


def test_attachments_locked_after_submission_and_security_stage(world):
    w = world
    d = submitted_approved_outward(w)
    assert w.creator.post(f"/gate-passes/{d['id']}/attachments", {"filename": "late.jpg", "size": 100}).status_code == 409
    upload(w.sec, d["id"], jpeg_bytes(), "gate.jpg", stage="GATE_OUT")                            # security may add gate evidence
    aid = w.creator.get(f"/gate-passes/{d['id']}").json()["attachments"][0]["id"]
    assert w.creator.post(f"/attachments/{aid}/delete", {"reason": "oops"}).status_code == 403   # cannot delete after submission
    # deletion before submission is soft and audited
    g2 = new_outward(w, with_photo=False)
    a2, _ = upload(w.creator, g2["id"], jpeg_bytes())
    assert w.creator.post(f"/attachments/{a2}/delete", {"reason": "retake"}).status_code == 200
    assert w.creator.get(f"/gate-passes/{g2['id']}").json()["attachments"] == []
    assert w.master.get("/audit-logs", params={"action": "attachment.delete"}).json()["total"] == 1


# ---------------- dynamic forms & versioning ----------------
def _field(key="driver_name", label="Driver Name", **kw):
    return {"key": key, "label": label, "type": "TEXT", "applies_to": ["OUTWARD"], **kw}


def test_form_builder_versioning_preserves_history(world):
    w = world
    old = submitted_approved_outward(w)                                         # created on v1
    v1 = old["form_version_id"]
    assert old["form_version_no"] == 1 and "driver_name" not in old["values"]
    # --- admin adds fields, renames, disables, reorders, makes dropdown ---
    assert w.master.post("/forms/OUTWARD/draft").status_code == 201
    assert w.master.post("/forms/OUTWARD/draft").status_code == 409             # one draft at a time
    assert w.master.post("/forms/draft/fields", _field("driver_name", "Driver Name", required=True, placeholder="Full name")).status_code == 201
    r = w.master.post("/forms/draft/fields", {"key": "cnic", "label": "CNIC", "type": "TEXT", "applies_to": ["OUTWARD"],
                                              "validation": {"regex": r"\d{5}-\d{7}-\d", "regex_message": "Format 12345-1234567-1"}})
    assert r.status_code == 201
    r = w.master.post("/forms/draft/fields", {"key": "transporter", "label": "Transporter", "type": "DROPDOWN", "applies_to": ["OUTWARD"],
                                              "options": [{"value": "OWN", "label": "Own"}, {"value": "TCS", "label": "TCS"}]})
    assert r.status_code == 201
    assert w.master.patch("/forms/OUTWARD/draft/fields/seal_no", {"label": "Seal Number"}).status_code == 200
    assert w.master.patch("/forms/OUTWARD/draft/fields/remarks", {"is_active": False}).status_code == 200       # disable a core field
    # locked system fields cannot be disabled / made optional
    assert w.master.patch("/forms/OUTWARD/draft/fields/quantity", {"is_active": False}).status_code == 403
    assert w.master.patch("/forms/OUTWARD/draft/fields/item_description", {"is_required": False}).json()["code"] == "FIELD_LOCKED"
    # mandatory policy fields cannot be made optional at publish
    w.master.patch("/forms/OUTWARD/draft/fields/location_id", {"is_required": False})
    pub = w.master.post("/forms/OUTWARD/draft/publish", {"change_note": "x"})
    assert pub.status_code == 422 and pub.json()["code"] == "PUBLISH_BLOCKED"
    w.master.patch("/forms/OUTWARD/draft/fields/location_id", {"is_required": True})
    assert w.creator.post("/forms/OUTWARD/draft/publish", {"change_note": "x"}).status_code == 403
    assert w.master.post("/forms/OUTWARD/draft/publish", {"change_note": ""}).status_code == 422
    diff = w.master.get("/forms/OUTWARD/draft/diff").json()
    assert set(diff["added"]) == {"driver_name", "cnic", "transporter"} and "remarks" in diff["disabled"]
    assert w.master.post("/forms/OUTWARD/draft/validate").json()["ok"] is True
    pub = w.master.post("/forms/OUTWARD/draft/publish", {"change_note": "Add driver details"})
    assert pub.status_code == 200 and pub.json() == {"OUTWARD": 2}
    # --- future passes use v2 ---
    pf = w.creator.get("/forms/OUTWARD/published").json()
    keys = {f["key"]: f for s in pf["snapshot"]["sections"] for f in s["fields"]}
    assert pf["version_no"] == 2 and keys["seal_no"]["label"] == "Seal Number" and keys["driver_name"]["required"] and keys["remarks"]["active"] is False
    new = w.creator.post("/gate-passes", {"type": "OUTWARD", "values": header(w, remarks=None, driver_name="Ali Raza", cnic="42101-1234567-1", transporter="TCS"), "items": [item(w)]})
    assert new.status_code == 201, new.text
    nd = new.json()
    assert nd["form_version_no"] == 2 and nd["values"]["driver_name"] == "Ali Raza" and nd["values"]["transporter"] == "TCS"
    bad = w.creator.post("/gate-passes", {"type": "OUTWARD", "values": header(w, remarks=None, cnic="123"), "items": [item(w)]})
    assert bad.status_code == 422 and bad.json()["details"]["errors"][0]["message"].startswith("Format")
    assert w.creator.post("/gate-passes", {"type": "OUTWARD", "values": header(w, remarks=None, transporter="DHL"), "items": [item(w)]}).status_code == 422
    # the disabled field is not accepted on new passes
    assert w.creator.post("/gate-passes", {"type": "OUTWARD", "values": header(w, remarks="hello"), "items": [item(w)]}).status_code == 422
    # --- historical pass is unchanged and still renders with the v1 structure ---
    again = w.audit.get(f"/gate-passes/{old['id']}").json()
    assert again["form_version_id"] == v1 and again["form_version_no"] == 1 and again["remarks"] == "test"
    f1 = {f["key"]: f for s in again["form_snapshot"]["sections"] for f in s["fields"]}
    assert f1["seal_no"]["label"] == "Seal #" and "driver_name" not in f1 and f1["remarks"]["active"] is True
    # published versions are immutable at the database level
    with pytest.raises(Exception, match="immutable|not a draft"):
        with tx() as c:
            q(c, "UPDATE form_versions SET snapshot = '{}'::jsonb WHERE id = :v", v=v1)
    with pytest.raises(Exception, match="not a draft"):
        with tx() as c:
            q(c, "UPDATE form_fields SET label = 'Hacked' WHERE form_version_id = :v", v=v1)
    with pytest.raises(Exception):
        with tx() as c:
            q(c, "DELETE FROM form_versions WHERE id = :v", v=v1)
    versions = w.master.get("/forms/OUTWARD/versions").json()
    assert [(v["version_no"], v["status"]) for v in versions] == [(2, "PUBLISHED"), (1, "ARCHIVED")] and versions[1]["gate_passes"] == 1
    # type of a published field is frozen; custom field deletion is only safe before publishing
    w.master.post("/forms/OUTWARD/draft")
    assert w.master.patch("/forms/OUTWARD/draft/fields/driver_name", {"type": "INTEGER"}).json()["code"] == "TYPE_FROZEN"
    assert w.master.delete("/forms/OUTWARD/draft/fields/driver_name").json()["code"] == "DELETE_NOT_SAFE"
    w.master.post("/forms/draft/fields", _field("temp_note", "Temp"))
    assert w.master.delete("/forms/OUTWARD/draft/fields/temp_note").status_code == 200
    # re-enable the disabled field and publish v3; draft passes keep their version until explicitly moved (D-17)
    draft_pass = w.creator.get(f"/gate-passes/{nd['id']}").json()
    w.master.patch("/forms/OUTWARD/draft/fields/remarks", {"is_active": True})
    assert w.master.post("/forms/OUTWARD/draft/publish", {"change_note": "re-enable remarks"}).json() == {"OUTWARD": 3}
    still = w.creator.get(f"/gate-passes/{nd['id']}").json()
    assert still["form_version_no"] == 2 and still["newer_form_available"] is True
    moved = w.creator.post(f"/gate-passes/{nd['id']}/move-to-latest-form").json()
    assert moved["form_version_no"] == 3 and moved["values"]["driver_name"] == "Ali Raza"


def test_dropdown_options_and_applies_to_both_forms(world):
    w = world
    r = w.master.post("/forms/draft/fields", {"key": "vehicle_type", "label": "Vehicle Type", "type": "DROPDOWN", "applies_to": ["OUTWARD", "INWARD"],
                                              "options": [{"value": "TRUCK", "label": "Truck"}, {"value": "VAN", "label": "Van"}]})
    assert r.status_code == 201 and set(r.json()) == {"OUTWARD", "INWARD"}
    assert w.master.put("/forms/INWARD/draft/fields/vehicle_type/options", {"options": [{"value": "BIKE", "label": "Bike"}, {"value": "VAN", "label": "Van"}]}).status_code == 200
    assert w.master.post("/forms/OUTWARD/draft/publish", {"change_note": "both", "also": ["INWARD"]}).json() == {"OUTWARD": 2, "INWARD": 2}
    assert w.creator.post("/gate-passes", {"type": "INWARD", "values": {"location_id": w.loc2, "responsible": {"name": "x"}, "inward_kind": "FRESH_INWARD", "vehicle_type": "BIKE"},
                                           "items": [item(w, returnable=False)]}).status_code == 201
    assert w.creator.post("/gate-passes", {"type": "INWARD", "values": {"location_id": w.loc2, "responsible": {"name": "x"}, "inward_kind": "FRESH_INWARD", "vehicle_type": "TRUCK"},
                                           "items": [item(w, returnable=False)]}).status_code == 422   # TRUCK exists only in the outward form


# ---------------- audit ----------------
def test_audit_log_is_append_only_and_chain_is_verifiable(world):
    w = world
    submitted_approved_outward(w)
    for sql in ("UPDATE audit_logs SET summary = 'x'", "DELETE FROM audit_logs", "TRUNCATE audit_logs"):
        with pytest.raises(Exception, match="append-only"):
            with tx() as c:
                q(c, sql)
    res = w.master.get("/audit-logs/verify-chain").json()
    assert res["ok"] is True and res["rows_checked"] > 10
    actions = {a["action"] for a in w.master.get("/audit-logs", params={"page_size": 100}).json()["items"]}
    assert {"gatepass.create", "gatepass.submit", "gatepass.approve.l1", "gatepass.approve.l2", "attachment.confirm", "auth.login.success"} <= actions
    # tampering through a privileged connection is detected by the hash chain
    with tx() as c:
        q(c, "SET LOCAL session_replication_role = replica")
        q(c, "UPDATE audit_logs SET summary = 'tampered' WHERE id = (SELECT min(id) + 3 FROM audit_logs)")
    bad = w.master.get("/audit-logs/verify-chain").json()
    assert bad["ok"] is False and bad["first_bad_audit_id"]
    with tx() as c:       # restore for the other tests
        q(c, "SET LOCAL session_replication_role = replica")
        q(c, "DELETE FROM audit_logs")
    assert w.creator.get("/audit-logs").status_code == 403


def test_status_history_and_transitions_are_enforced_by_the_database(world):
    w = world
    d = submitted_approved_outward(w)
    with pytest.raises(Exception, match="invalid gate pass status transition"):
        with tx() as c:
            q(c, "UPDATE gate_passes SET status = 'CLOSED', closed_at = now() WHERE id = :i", i=d["id"])
    with pytest.raises(Exception, match="lacks a history row"):
        with tx() as c:
            q(c, "UPDATE gate_passes SET status = 'GATE_OUT' WHERE id = :i", i=d["id"])
    with pytest.raises(Exception, match="immutable"):
        with tx() as c:
            q(c, "UPDATE gate_pass_items SET quantity = 99 WHERE gate_pass_id = :i", i=d["id"])         # D-19 at DB level
    with pytest.raises(Exception, match="append-only"):
        with tx() as c:
            q(c, "DELETE FROM gate_pass_approvals")
    with pytest.raises(Exception, match="duplicate key|uq_"):
        with tx() as c:
            q(c, "UPDATE gate_passes SET gate_pass_no = (SELECT gate_pass_no FROM gate_passes LIMIT 1) WHERE id <> (SELECT id FROM gate_passes LIMIT 1)")
            q(c, "INSERT INTO gate_passes (gate_pass_no, type_id, form_version_id, created_by, status) SELECT gate_pass_no, type_id, form_version_id, created_by, 'PENDING_L1' FROM gate_passes LIMIT 1")
