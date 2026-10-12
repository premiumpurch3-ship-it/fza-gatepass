import io
import os
import shutil
import tempfile
import uuid
from datetime import date, timedelta
from pathlib import Path

import pytest

TEST_DB = os.environ.get("TEST_DATABASE_URL", "postgresql+psycopg://gatepass:devpass@127.0.0.1:5432/gatepass_test")
os.environ["DATABASE_URL"] = TEST_DB
os.environ["ENV"] = "test"
os.environ["ARGON2_TIME_COST"] = "1"
os.environ["ARGON2_MEMORY_KIB"] = "1024"
os.environ["LOCAL_STORAGE_DIR"] = tempfile.mkdtemp(prefix="gp_storage_")
os.environ["PUBLIC_BASE_URL"] = "http://testserver"
os.environ["SECRET_KEY"] = "test-secret-key-test-secret-key-test-secret-key"
os.environ["APP_ENCRYPTION_KEY"] = "test-encryption-key-test-encryption-key"

import pyotp  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from PIL import Image  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

PW = "TestPassw0rd!"
_MASTER: dict = {}
BACKEND = Path(__file__).resolve().parents[1]
TRANSACTIONAL = ("gate_passes", "notifications", "idempotency_keys", "login_attempts", "background_jobs", "export_jobs", "number_sequences")


@pytest.fixture(scope="session", autouse=True)
def _database():
    eng = create_engine(TEST_DB, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    command.upgrade(cfg, "head")
    from app import cli
    cli.seed()
    yield
    shutil.rmtree(os.environ["LOCAL_STORAGE_DIR"], ignore_errors=True)


@pytest.fixture(autouse=True)
def _clean():
    from app.core import settings_store
    eng = create_engine(TEST_DB)
    with eng.begin() as c:
        c.execute(text("SET session_replication_role = replica"))
        c.execute(text(f"TRUNCATE {', '.join(TRANSACTIONAL)} RESTART IDENTITY CASCADE"))
        c.execute(text("TRUNCATE form_field_options, form_fields, form_sections, form_versions, form_definitions, form_field_registry RESTART IDENTITY CASCADE"))
    from app.core.db import tx
    from app.services import forms_seed
    with tx() as c2:                      # every test starts from the pristine v1 forms
        forms_seed.seed_forms(c2)
    settings_store.invalidate()
    from app.core import rbac
    rbac._cache.clear()
    yield


@pytest.fixture(scope="session")
def client():
    from app.main import app
    with TestClient(app, raise_server_exceptions=False, headers={"x-client-platform": "android"}) as c:
        yield c


class U:
    def __init__(self, client, id_, username, token=None):
        self.client, self.id, self.username, self.token = client, id_, username, token

    @property
    def h(self):
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, url, **kw):
        return self.client.get("/api/v1" + url, headers=self.h, **kw)

    def post(self, url, json=None, key=None, **kw):
        h = {**self.h, **({"Idempotency-Key": key} if key else {})}
        return self.client.post("/api/v1" + url, json=json if json is not None else {}, headers=h, **kw)

    def put(self, url, json=None, **kw):
        return self.client.put("/api/v1" + url, json=json, headers=self.h, **kw)

    def patch(self, url, json=None, **kw):
        return self.client.patch("/api/v1" + url, json=json, headers=self.h, **kw)

    def delete(self, url, **kw):
        return self.client.delete("/api/v1" + url, headers=self.h, **kw)


def _login(client, username, password=PW, totp=None):
    body = {"username": username, "password": password, **({"totp": totp} if totp else {})}
    return client.post("/api/v1/auth/login", json=body)


@pytest.fixture
def make_user(client):
    from app.core.db import one, q, tx
    from app.core.security import hash_password

    def _make(roles=(), perms_grant=(), master=False, name=None, mfa_secret=None):
        if master and _MASTER:
            r = _login(client, _MASTER["username"], totp=pyotp.TOTP(_MASTER["secret"]).now())
            assert r.status_code == 200, r.text
            user = U(client, _MASTER["id"], _MASTER["username"], r.json()["access_token"])
            user.secret = _MASTER["secret"]
            return user
        un = (name or "u" + uuid.uuid4().hex[:8]).lower()
        with tx() as c:
            secret = None
            if master:
                from app.core.security import encrypt_secret
                secret = mfa_secret or pyotp.random_base32()
            u = one(c, """INSERT INTO users (username, full_name, email, password_hash, must_change_password, is_master_admin, mfa_enabled, mfa_secret_enc)
                          VALUES (:u, :n, :e, :p, false, :m, :me, :s) RETURNING id""", u=un, n=f"User {un}", e=f"{un}@example.test", p=hash_password(PW), m=master,
                    me=master, s=encrypt_secret(secret) if master else None)
            for r in roles:
                q(c, "INSERT INTO user_roles (user_id, role_id) SELECT :u, id FROM roles WHERE code = :r", u=u["id"], r=r)
            for p in perms_grant:
                q(c, "INSERT INTO user_permissions (user_id, permission_code, effect) VALUES (:u, :p, 'GRANT')", u=u["id"], p=p)
        r = _login(client, un, totp=pyotp.TOTP(secret).now() if master else None)
        assert r.status_code == 200, r.text
        user = U(client, str(u["id"]), un, r.json()["access_token"])
        user.secret = secret
        if master:
            _MASTER.update(username=un, secret=secret, id=str(u["id"]))
        return user
    return _make


@pytest.fixture
def world(make_user):
    """The standard cast from the acceptance criteria."""
    from app.core.db import one, q, tx
    w = type("W", (), {})()
    w.creator = make_user(["gatepass_creator"])
    w.creator2 = make_user(["gatepass_creator"])
    w.a1 = make_user(["approver_l1"])
    w.a2 = make_user(["approver_l2"])
    w.inward_appr = make_user(["inward_approver"])
    w.sec = make_user(["security_officer"])
    w.audit = make_user(["admin_auditor"])
    w.reporter = make_user(["reporter"])
    w.master = make_user(master=True)
    with tx() as c:
        w.loc = str(one(c, "SELECT id FROM locations WHERE code = 'MAIN'")["id"])
        w.pcs = str(one(c, "SELECT id FROM units_of_measure WHERE code = 'PCS'")["id"])
        w.kg = str(one(c, "SELECT id FROM units_of_measure WHERE code = 'KG'")["id"])
        w.loc2 = str(one(c, """INSERT INTO locations (code, name) VALUES ('HO', 'Head Office') ON CONFLICT (code) DO UPDATE SET name = 'Head Office' RETURNING id""")["id"])
    return w


def jpeg_bytes(size=(64, 48), color=(200, 30, 30)):
    b = io.BytesIO()
    Image.new("RGB", size, color).save(b, "JPEG")
    return b.getvalue()


def upload(user, gp_id, data: bytes, filename="photo.jpg", stage="CREATION", captured=True, expect_confirm=200):
    r = user.post(f"/gate-passes/{gp_id}/attachments", {"filename": filename, "size": len(data), "stage": stage, "captured": captured})
    assert r.status_code == 201, r.text
    j = r.json()
    path = j["upload"]["url"].replace("http://testserver", "")
    pr = user.client.put(path, content=data, headers={"Content-Type": j["upload"]["headers"]["Content-Type"]})
    assert pr.status_code == 200, pr.text
    cr = user.post(f"/attachments/{j['id']}/confirm")
    assert cr.status_code == expect_confirm, cr.text
    return j["id"], cr


def item(w, desc="Laptop", qty=10, returnable=True, unit=None, **extra):
    return {"values": {"item_description": desc, "quantity": qty, "unit_id": unit or w.pcs, "is_returnable": returnable, **extra}}


def header(w, **over):
    h = {"location_id": w.loc2, "responsible": {"name": "Rashid Khan"}, "reference_no": "REF-1", "vehicle_no": "ABC-123", "seal_no": "S-1",
         "expected_return_date": (date.today() + timedelta(days=10)).isoformat(), "remarks": "test"}
    h.update(over)
    return {k: v for k, v in h.items() if v is not None}


def new_outward(w, items=None, with_photo=True, **hdr):
    r = w.creator.post("/gate-passes", {"type": "OUTWARD", "values": header(w, **hdr), "items": items or [item(w)]})
    assert r.status_code == 201, r.text
    gp = r.json()
    if with_photo:
        upload(w.creator, gp["id"], jpeg_bytes())
    return gp


def approve_outward(w, gp_id):
    assert w.a1.post(f"/gate-passes/{gp_id}/approve", {"comments": "ok"}).status_code == 200
    r = w.a2.post(f"/gate-passes/{gp_id}/approve", {})
    assert r.status_code == 200, r.text
    return r.json()


def submitted_approved_outward(w, items=None, **hdr):
    gp = new_outward(w, items, **hdr)
    r = w.creator.post(f"/gate-passes/{gp['id']}/submit")
    assert r.status_code == 200, r.text
    return approve_outward(w, gp["id"])


def gate_out(w, gp_id, **body):
    r = w.sec.post(f"/gate-passes/{gp_id}/gate-out", body)
    assert r.status_code == 200, r.text
    return r.json()


def returned_inward(w, outward_id, qty, submit=True, approve=True, gate=True, line=0):
    """Create (+submit/approve/gate-in) an inward pass returning `qty` of outward line `line`. Returns the inward detail."""
    lines = w.creator.get(f"/gate-passes/{outward_id}/returnable-lines").json()
    ln = lines[line]
    items = [{"source_outward_item_id": ln["source_outward_item_id"], "values": {"item_description": ln["description"], "quantity": qty, "unit_id": ln["unit_id"], "is_returnable": False}}]
    r = w.creator.post("/gate-passes", {"type": "INWARD", "values": {"location_id": w.loc2, "responsible": {"name": "Rashid"}, "inward_kind": "RETURN_AGAINST_OUTWARD"}, "items": items})
    assert r.status_code == 201, r.text
    gp = r.json()
    if submit:
        sr = w.creator.post(f"/gate-passes/{gp['id']}/submit")
        if sr.status_code != 200:
            return sr
    if approve:
        assert w.inward_appr.post(f"/gate-passes/{gp['id']}/approve", {}).status_code == 200
    if gate:
        return w.sec.post(f"/gate-passes/{gp['id']}/gate-in", {})
    return w.creator.get(f"/gate-passes/{gp['id']}")
