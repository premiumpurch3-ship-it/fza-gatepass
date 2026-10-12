#!/bin/sh
# One-shot: schema migrations (as owner) + least-privilege grants for the application role + idempotent seed data.
set -e
python -m alembic upgrade head
python -m app.cli apply-grants
python -m app.cli seed
echo "migrations, grants and seed complete"
