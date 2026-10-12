import logging
from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError

log = logging.getLogger("gatepass")


class AppError(Exception):
    def __init__(self, code: str, message: str, status: int = 400, details: dict | None = None):
        self.code, self.message, self.status, self.details = code, message, status, details or {}


def NotFound(what="Record"):
    return AppError("NOT_FOUND", f"{what} not found", 404)


def Forbidden(msg="You do not have permission to perform this action", code="FORBIDDEN"):
    return AppError(code, msg, 403)


def Conflict(code: str, msg: str, **details):
    return AppError(code, msg, 409, details)


def Invalid(msg: str, code="VALIDATION_ERROR", **details):
    return AppError(code, msg, 422, details)


def problem(status: int, code: str, message: str, details=None, request: Request | None = None):
    body = {"type": f"https://gatepass.mtj/errors/{code}", "title": code, "status": status, "code": code,
            "detail": message, "details": details or {}}
    if request is not None:
        body["request_id"] = getattr(request.state, "request_id", None)
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


async def app_error_handler(request: Request, exc: AppError):
    return problem(exc.status, exc.code, exc.message, exc.details, request)


async def db_error_handler(request: Request, exc: DBAPIError):
    # Never leak SQL/stack traces. Known constraint violations become 409/422; everything else is 500.
    msg = str(getattr(exc, "orig", exc))
    log.warning("db error: %s", msg.splitlines()[0] if msg else msg)
    if "invalid gate pass status transition" in msg:
        return problem(409, "INVALID_TRANSITION", "That action is not allowed in the current state", request=request)
    if "ck_ri__no_overreturn" in msg:
        return problem(409, "RETURN_EXCEEDS_PENDING", "Returned quantity cannot exceed the pending quantity", request=request)
    if "immutable" in msg or "append-only" in msg or "not a draft" in msg:
        return problem(409, "IMMUTABLE_RECORD", "This record can no longer be changed", request=request)
    if "unique" in msg.lower() or "duplicate key" in msg.lower():
        return problem(409, "DUPLICATE", "A record with the same unique value already exists", request=request)
    return problem(500, "INTERNAL_ERROR", "An internal error occurred", request=request)


async def unhandled_handler(request: Request, exc: Exception):
    log.exception("unhandled error")
    return problem(500, "INTERNAL_ERROR", "An internal error occurred", request=request)
