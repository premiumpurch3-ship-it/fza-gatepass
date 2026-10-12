"""initial schema (see sql/0001_schema.sql)"""
from pathlib import Path
from alembic import op

revision = "0001"
down_revision = None
SQL = Path(__file__).resolve().parents[2] / "sql" / "0001_schema.sql"

def upgrade():
    op.get_bind().connection.driver_connection.execute(SQL.read_text())

def downgrade():
    raise RuntimeError("forward-only migration; restore from backup instead")
