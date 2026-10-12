FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 postgresql-client curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN useradd -r -u 10001 -m gatepass && mkdir -p /app/storage_data && chown -R gatepass /app
USER gatepass
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --retries=5 CMD curl -fs http://localhost:8000/health || exit 1
# api: gunicorn with uvicorn workers; worker: `python -m app.worker`; migrate: `sh scripts/migrate.sh`
CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", "-w", "3", "-b", "0.0.0.0:8000", "--forwarded-allow-ips", "*", "--access-logfile", "-"]
