from alembic import context
from sqlalchemy import create_engine
from app.core.config import settings

def run():
    import os
    engine = create_engine(os.environ.get('MIGRATION_DATABASE_URL') or settings.database_url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()
run()
