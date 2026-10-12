import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from .api import admin, auth, forms, gatepasses, ops
from .core import deps
from .core.config import settings
from .core.db import engine
from .core.errors import AppError, app_error_handler, db_error_handler, unhandled_handler, problem

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
settings.assert_production_safe()

app = FastAPI(title="FZA-GatePass-MTJ API", version="1.0.0", docs_url="/api/docs" if settings.docs_enabled else None,
              redoc_url=None, openapi_url="/api/openapi.json" if settings.docs_enabled else None)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_list, allow_credentials=True,
                   allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                   allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID", "X-Client-Platform", "X-Client-Version", "X-Requested-With"],
                   expose_headers=["X-Request-ID", "Idempotent-Replay", "Content-Disposition"])
app.middleware("http")(deps.request_context_middleware)
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(DBAPIError, db_error_handler)
app.add_exception_handler(Exception, unhandled_handler)

from fastapi.exceptions import RequestValidationError


@app.exception_handler(RequestValidationError)
async def validation_handler(request, exc):
    errs = [{"field": ".".join(str(x) for x in e["loc"][1:]), "message": e["msg"]} for e in exc.errors()]
    return problem(422, "VALIDATION_ERROR", "Invalid request", {"errors": errs}, request)


P = "/api/v1"
for r in (auth.router, admin.router, forms.router, gatepasses.router, ops.workflow, ops.attachments, ops.local, ops.notif, ops.rep, ops.audit_r):
    app.include_router(r, prefix=P)


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}


@app.get("/health/ready", tags=["system"])
def ready():
    with engine.connect() as c:
        c.execute(text("SELECT 1"))
    from .storage import get_storage
    get_storage()
    return {"status": "ready"}
