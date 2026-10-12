#!/bin/bash
# Self-contained end-to-end run: PostgreSQL + FastAPI + Next.js (production build) + headless Chromium.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export DATABASE_URL=${DATABASE_URL:-postgresql+psycopg://gatepass:devpass@127.0.0.1:5432/gatepass_dev} ENV=development
pg_isready -h 127.0.0.1 -q || { service postgresql start >/dev/null 2>&1; sleep 4; }
cd "$ROOT/backend" && . .venv/bin/activate && python ../e2e/prepare_db.py
rm -rf /tmp/e2e_storage && mkdir -p /tmp/e2e_storage
LOCAL_STORAGE_DIR=/tmp/e2e_storage PUBLIC_BASE_URL=http://localhost:3000 CORS_ORIGINS=http://localhost:3000 uvicorn app.main:app --port 8000 > /tmp/uvicorn.log 2>&1 &
API=$!
cd "$ROOT/frontend" && PORT=3000 npm run start > /tmp/next.log 2>&1 &
WEB=$!
trap "kill $API $WEB 2>/dev/null" EXIT
for i in $(seq 1 40); do curl -sf localhost:3000/api/v1/settings/public >/dev/null && break; sleep 1; done
cd "$ROOT/backend" && python ${E2E_SCRIPT:-../e2e/walkthrough.py}
