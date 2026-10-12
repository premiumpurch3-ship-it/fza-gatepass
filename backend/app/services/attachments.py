"""Attachments: presigned upload -> server-side validation (extension, MIME by magic bytes, size) -> processing (HEIC->JPEG, metadata strip, thumbnail)."""
import hashlib
import io
import zipfile
from datetime import datetime

import magic
from PIL import Image, ImageOps

from ..core import settings_store as ss
from ..core.audit import audit
from ..core.db import J, one, q, rows, scalar, tx
from ..core.errors import AppError, Conflict, Forbidden, Invalid, NotFound
from ..storage import get_storage
from . import gatepass as gp_svc

try:
    import pillow_heif
    pillow_heif.register_heif_opener()
except Exception:   # pragma: no cover
    pillow_heif = None
Image.MAX_IMAGE_PIXELS = 60_000_000

IMAGE_EXT, VIDEO_EXT, DOC_EXT = {"jpg", "jpeg", "png", "heic", "heif"}, {"mp4", "mov", "webm", "m4v"}, {"pdf", "doc", "docx", "xls", "xlsx"}
MIME_OK = {
    "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"}, "png": {"image/png"}, "heic": {"image/heic", "image/heif"}, "heif": {"image/heic", "image/heif"},
    "pdf": {"application/pdf"}, "mp4": {"video/mp4", "video/x-m4v", "video/quicktime"}, "m4v": {"video/mp4", "video/x-m4v", "video/quicktime"},
    "mov": {"video/quicktime", "video/mp4"}, "webm": {"video/webm"},
    "doc": {"application/msword", "application/cdfv2", "application/x-ole-storage", "application/vnd.ms-office"},
    "xls": {"application/vnd.ms-excel", "application/cdfv2", "application/x-ole-storage", "application/vnd.ms-office"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip", "application/octet-stream"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip", "application/octet-stream"},
}
CONTENT_TYPE = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "heic": "image/heic", "heif": "image/heif", "pdf": "application/pdf",
                "mp4": "video/mp4", "m4v": "video/x-m4v", "mov": "video/quicktime", "webm": "video/webm", "doc": "application/msword",
                "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "xls": "application/vnd.ms-excel",
                "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
INLINE_OK = {"image/jpeg", "image/png", "application/pdf", "video/mp4", "video/webm", "video/quicktime"}


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _safe_name(n: str) -> str:
    n = "".join(ch for ch in n if ch.isprintable() and ch not in '\\/:*?"<>|')[:150].strip()
    return n or "file"


def _limit_mb(c, ext):
    key = "attachments.max_image_mb" if ext in IMAGE_EXT else "attachments.max_video_mb" if ext in VIDEO_EXT else "attachments.max_document_mb"
    return ss.get(key, c)


def register(user, gp_id, body: dict):
    if "attachment.upload" not in user["perms"]:
        raise Forbidden()
    name = _safe_name(body["filename"])
    ext = _ext(name)
    stage = body.get("stage") or "CREATION"
    with tx() as c:
        allowed = set(ss.get("attachments.allowed_extensions", c) or [])
        if ext not in MIME_OK or ext not in allowed:
            raise Invalid(f"File type .{ext} is not allowed", "FILE_TYPE_NOT_ALLOWED")
        gp = gp_svc.load(c, gp_id, lock=True)
        gp_svc.check_visible(c, user, gp_id)
        st = gp["status"]
        if stage == "CREATION":
            if gp["created_by"] != user["id"] or st not in gp_svc.EDITABLE:
                raise Conflict("NOT_EDITABLE", "Attachments can only be added to your own draft or rejected gate passes")
        elif stage == "GATE_OUT":
            if "security.gateout" not in user["perms"] or gp["direction"] != "OUT" or st != "APPROVED":
                raise Forbidden()
        elif stage == "GATE_IN":
            if "security.gatein" not in user["perms"] or gp["direction"] != "IN" or st != "APPROVED":
                raise Forbidden()
        elif stage == "ADMIN":
            if "admin.verify" not in user["perms"] or st == "DRAFT":
                raise Forbidden()
        else:
            raise Invalid("Invalid stage", "VALIDATION_ERROR")
        size = int(body["size"])
        mx = _limit_mb(c, ext) * 1024 * 1024
        if size <= 0 or size > mx:
            raise Invalid(f"File is too large (maximum {_limit_mb(c, ext)} MB)", "FILE_TOO_LARGE")
        if scalar(c, "SELECT count(*) FROM gate_pass_attachments WHERE gate_pass_id = :g AND status <> 'DELETED'", g=gp["id"]) >= ss.get("attachments.max_files_per_pass", c):
            raise Invalid("Too many attachments on this gate pass", "TOO_MANY_FILES")
        item_id = body.get("item_id")
        if item_id and not one(c, "SELECT 1 AS x FROM gate_pass_items WHERE id = CAST(:i AS uuid) AND gate_pass_id = :g", i=item_id, g=gp["id"]):
            raise Invalid("Unknown item", "VALIDATION_ERROR")
        kind = ("PHOTO_CAPTURE" if body.get("captured") else "PHOTO_UPLOAD") if ext in IMAGE_EXT else "VIDEO" if ext in VIDEO_EXT else "DOCUMENT"
        seq = scalar(c, "SELECT coalesce(max(sequence_no), 0) + 1 FROM gate_pass_attachments WHERE gate_pass_id = :g", g=gp["id"])
        now = datetime.utcnow()
        a = one(c, """INSERT INTO gate_pass_attachments (gate_pass_id, gate_pass_item_id, kind, stage, sequence_no, original_filename, storage_key, declared_mime, extension,
                      capture_meta, uploaded_by) VALUES (:g, CAST(:i AS uuid), :k, :s, :n, :f, 'pending/' || gen_random_uuid()::text, :dm, :e, CAST(:cm AS jsonb), :u) RETURNING id""",
                g=gp["id"], i=item_id, k=kind, s=stage, n=seq, f=name, dm=(body.get("content_type") or "")[:100], e=ext, cm=J(body.get("capture_meta") or {}), u=user["id"])
        key = f"gatepass/{now:%Y}/{now:%m}/{gp['id']}/{a['id']}.{ext}"
        q(c, "UPDATE gate_pass_attachments SET storage_key = :k WHERE id = :i", k=key, i=a["id"])
        up = get_storage().presign_put(key, CONTENT_TYPE[ext], mx)
        audit(c, "attachment.register", "attachment", a["id"], f"Upload registered: {name}", gate_pass_id=gp["id"], after={"kind": kind, "size": size, "stage": stage})
        return {"id": a["id"], "upload": up, "expires_in": 900, "kind": kind, "sequence_no": seq}


def _detect(ext: str, data_head: bytes, full: bytes | None):
    m = magic.from_buffer(data_head, mime=True).lower()
    ok = m in MIME_OK[ext]
    if ext in ("docx", "xlsx") and full is not None:
        try:
            names = zipfile.ZipFile(io.BytesIO(full)).namelist()
            ok = ok and ("word/document.xml" in names if ext == "docx" else "xl/workbook.xml" in names)
        except zipfile.BadZipFile:
            ok = False
    if ext in ("doc", "xls"):
        ok = ok and data_head[:8] == bytes.fromhex("D0CF11E0A1B11AE1")
    return m, ok


def _quarantine(c, a, reason, mime=None):
    q(c, "UPDATE gate_pass_attachments SET status = 'QUARANTINED', detected_mime = :m WHERE id = :i", m=mime, i=a["id"])
    audit(c, "attachment.quarantine", "attachment", a["id"], f"File rejected: {reason}", gate_pass_id=a["gate_pass_id"], severity="WARN", after={"reason": reason, "detected": mime})


def confirm(user, att_id):
    """Quarantine decisions must be committed (status + audit) *before* the error is raised, so the work happens in `_confirm` and errors are raised after commit."""
    res, err = _confirm(user, att_id)
    if err:
        raise err
    return res


def _confirm(user, att_id):
    st = get_storage()
    with tx() as c:
        a = one(c, "SELECT * FROM gate_pass_attachments WHERE id = CAST(:i AS uuid) FOR UPDATE", i=str(att_id))
        if not a or a["uploaded_by"] != user["id"]:
            raise NotFound("Attachment")
        if a["status"] != "PENDING_UPLOAD":
            if a["status"] == "READY":
                return _public(a), None
            raise Conflict("INVALID_STATE", "Attachment cannot be confirmed in its current state")
        head = st.head(a["storage_key"])
        if not head:
            raise Invalid("The file has not been uploaded yet", "UPLOAD_MISSING")
        ext, size = a["extension"], head["size"]
        if size <= 0 or size > _limit_mb(c, ext) * 1024 * 1024:
            st.delete(a["storage_key"])
            _quarantine(c, a, "size limit exceeded")
            return None, Invalid("File is too large", "FILE_TOO_LARGE")
        full = st.read_all(a["storage_key"]) if ext not in VIDEO_EXT else None
        mime, ok = _detect(ext, full[:4096] if full is not None else st.get_range(a["storage_key"], 0, 4095), full)
        if not ok:
            st.delete(a["storage_key"])
            _quarantine(c, a, f"content ({mime}) does not match .{ext}", mime)
            return None, Invalid("The file content does not match its type and was rejected", "FILE_TYPE_MISMATCH")
        upd = {"detected_mime": mime, "size_bytes": size, "extension": ext, "storage_key": a["storage_key"], "sha256": None, "width": None, "height": None, "thumb": None, "name": a["original_filename"]}
        if ext in IMAGE_EXT:
            try:
                im = Image.open(io.BytesIO(full))
                im.load()
                im = ImageOps.exif_transpose(im)
                if im.mode not in ("RGB", "L"):
                    im = im.convert("RGB")
                out = io.BytesIO()
                if ext in ("heic", "heif"):        # D-15: HEIC -> JPEG
                    im.convert("RGB").save(out, "JPEG", quality=90)
                    newkey = a["storage_key"].rsplit(".", 1)[0] + ".jpg"
                    st.put_bytes(newkey, out.getvalue(), "image/jpeg")
                    st.delete(a["storage_key"])
                    upd.update(storage_key=newkey, extension="jpg", detected_mime="image/jpeg", name=a["original_filename"].rsplit(".", 1)[0] + ".jpg")
                elif ext == "png":
                    im.save(out, "PNG", optimize=True)
                    st.put_bytes(a["storage_key"], out.getvalue(), "image/png")
                else:
                    im.convert("RGB").save(out, "JPEG", quality=92)     # re-encode strips EXIF/GPS (D-14: no GPS)
                    st.put_bytes(a["storage_key"], out.getvalue(), "image/jpeg")
                data = out.getvalue()
                upd.update(size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), width=im.width, height=im.height)
                th = im.copy()
                th.thumbnail((320, 320))
                tb = io.BytesIO()
                th.convert("RGB").save(tb, "JPEG", quality=80)
                tkey = upd["storage_key"].rsplit(".", 1)[0] + ".thumb.jpg"
                st.put_bytes(tkey, tb.getvalue(), "image/jpeg")
                upd["thumb"] = tkey
            except Exception:
                st.delete(a["storage_key"])
                _quarantine(c, a, "image could not be decoded", mime)
                return None, Invalid("The image could not be read and was rejected", "FILE_TYPE_MISMATCH")
        elif full is not None:
            upd["sha256"] = hashlib.sha256(full).hexdigest()
        else:
            q(c, "INSERT INTO background_jobs (job_type, payload, dedupe_key) VALUES ('attachment.hash', CAST(:p AS jsonb), :d) ON CONFLICT (dedupe_key) DO NOTHING",
              p=J({"attachment_id": str(a["id"])}), d=f"hash:{a['id']}")
        q(c, """UPDATE gate_pass_attachments SET status = 'READY', detected_mime = :detected_mime, size_bytes = :size_bytes, extension = :extension, storage_key = :storage_key,
                sha256 = :sha256, width = :width, height = :height, thumbnail_key = :thumb, original_filename = :name WHERE id = :id""", id=a["id"], **upd)
        audit(c, "attachment.confirm", "attachment", a["id"], f"File attached: {upd['name']}", gate_pass_id=a["gate_pass_id"], after={"mime": upd["detected_mime"], "size": upd["size_bytes"], "kind": a["kind"]})
        return _public(one(c, "SELECT * FROM gate_pass_attachments WHERE id = :i", i=a["id"])), None


def _public(a):
    return {k: a[k] for k in ("id", "kind", "stage", "sequence_no", "original_filename", "detected_mime", "size_bytes", "status", "uploaded_at", "width", "height") if k in a} | \
           {"has_thumbnail": a.get("thumbnail_key") is not None}


def upload_proxy(user, att_id, data: bytes, content_type: str):
    """Fallback when direct-to-storage upload is not possible (blocked network). Same validation happens at confirm()."""
    with tx() as c:
        a = one(c, "SELECT * FROM gate_pass_attachments WHERE id = CAST(:i AS uuid)", i=str(att_id))
        if not a or a["uploaded_by"] != user["id"] or a["status"] != "PENDING_UPLOAD":
            raise NotFound("Attachment")
        if len(data) > _limit_mb(c, a["extension"]) * 1024 * 1024:
            raise Invalid("File is too large", "FILE_TOO_LARGE")
    get_storage().put_bytes(a["storage_key"], data, CONTENT_TYPE[a["extension"]])


def list_for_pass(user, gp_id):
    if "attachment.view" not in user["perms"]:
        raise Forbidden()
    with tx() as c:
        gp_svc.check_visible(c, user, gp_id)
        return [_public(a) for a in rows(c, "SELECT * FROM gate_pass_attachments WHERE gate_pass_id = :g AND status <> 'DELETED' ORDER BY sequence_no", g=gp_id)]


def download(user, att_id, thumbnail=False):
    if "attachment.view" not in user["perms"]:
        raise Forbidden()
    with tx() as c:
        a = one(c, "SELECT * FROM gate_pass_attachments WHERE id = CAST(:i AS uuid)", i=str(att_id))
        if not a:
            raise NotFound("Attachment")
        gp_svc.check_visible(c, user, a["gate_pass_id"])
        if a["status"] != "READY":
            raise NotFound("Attachment")
        key = a["thumbnail_key"] if thumbnail and a["thumbnail_key"] else a["storage_key"]
        mime = "image/jpeg" if key.endswith(".thumb.jpg") else a["detected_mime"]
        audit(c, "attachment.view" if thumbnail else "attachment.download", "attachment", a["id"], f"{'Viewed' if thumbnail else 'Downloaded'}: {a['original_filename']}", gate_pass_id=a["gate_pass_id"])
    inline = mime in INLINE_OK
    return {"url": get_storage().presign_get(key, a["original_filename"], mime, inline, 60), "expires_in": 60, "filename": a["original_filename"], "mime": mime}


def delete(user, att_id, reason):
    if "attachment.delete" not in user["perms"]:
        raise Forbidden()
    if not (reason or "").strip():
        raise Invalid("A reason is required", "REASON_REQUIRED")
    with tx() as c:
        a = one(c, "SELECT * FROM gate_pass_attachments WHERE id = CAST(:i AS uuid) FOR UPDATE", i=str(att_id))
        if not a or a["status"] == "DELETED":
            raise NotFound("Attachment")
        gp = gp_svc.load(c, a["gate_pass_id"], lock=True)
        if a["uploaded_by"] != user["id"] or gp["status"] not in gp_svc.EDITABLE or a["stage"] != "CREATION":
            raise Forbidden("Attachments can only be removed by their uploader before submission")
        q(c, "UPDATE gate_pass_attachments SET status = 'DELETED', deleted_at = now(), deleted_by = :u, delete_reason = :r WHERE id = :i", u=user["id"], r=reason.strip(), i=a["id"])
        audit(c, "attachment.delete", "attachment", a["id"], f"Attachment removed: {a['original_filename']}", gate_pass_id=a["gate_pass_id"], after={"reason": reason.strip()})


def process_hash_job(attachment_id: str):
    st = get_storage()
    with tx() as c:
        a = one(c, "SELECT storage_key FROM gate_pass_attachments WHERE id = CAST(:i AS uuid)", i=attachment_id)
        if not a:
            return
        h = hashlib.sha256()
        for chunk in st.iter_bytes(a["storage_key"]):
            h.update(chunk)
        q(c, "UPDATE gate_pass_attachments SET sha256 = :h WHERE id = CAST(:i AS uuid)", h=h.hexdigest(), i=attachment_id)
