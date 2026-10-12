"""Prepare a clean development database for the end-to-end run: migrations, seed, demo users, a Master Admin with a known TOTP secret."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from sqlalchemy import create_engine, text
from alembic import command
from alembic.config import Config
url = os.environ["DATABASE_URL"]
eng = create_engine(url, isolation_level="AUTOCOMMIT")
with eng.connect() as c:
    c.execute(text("DROP SCHEMA public CASCADE")); c.execute(text("CREATE SCHEMA public"))
B = os.path.join(os.path.dirname(__file__), "..", "backend")
cfg = Config(os.path.join(B, "alembic.ini")); cfg.set_main_option("script_location", os.path.join(B, "alembic"))
command.upgrade(cfg, "head")
from app import cli
cli.seed(); cli.seed_dev_users()
cli._create_master("mjadmin", "Master Administrator", "MasterPassw0rd!2026", secret="JBSWY3DPEHPK3PXP", code=__import__("pyotp").TOTP("JBSWY3DPEHPK3PXP").now(), interactive=False)
from app.core.db import tx, q
with tx() as c:     # give the demo creator all it needs for the walkthrough, plus an inward approver at L1 for the demo
    q(c, "INSERT INTO user_roles (user_id, role_id) SELECT u.id, r.id FROM users u, roles r WHERE u.username = 'inward_appr' AND r.code = 'inward_approver' ON CONFLICT DO NOTHING")
print("db ready")
