"""Idempotency for mutating calls: a client-generated `Idempotency-Key` header makes retries safe (no duplicate submit / approval / return)."""
import hashlib
import json
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from fastapi.routing import APIRoute
from jwt import PyJWTError
from starlette.responses import JSONResponse

from .db import J, one, q, tx
from .errors import problem
from .security import decode_access_token


class IdempotentRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            key = request.headers.get("idempotency-key")
            if request.method != "POST" or not key:
                return await original(request)
            auth = request.headers.get("authorization", "")
            try:
                uid = decode_access_token(auth.split(" ", 1)[1])["sub"]
            except (PyJWTError, IndexError, KeyError):
                return await original(request)
            if len(key) > 100:
                return problem(422, "INVALID_IDEMPOTENCY_KEY", "Idempotency-Key is too long", request=request)
            body = await request.body()
            h = hashlib.sha256(request.method.encode() + request.url.path.encode() + body).hexdigest()
            with tx() as c:
                q(c, "DELETE FROM idempotency_keys WHERE user_id = CAST(:u AS uuid) AND key = :k AND expires_at < now()", u=uid, k=key)
                ins = one(c, """INSERT INTO idempotency_keys (user_id, key, endpoint, request_hash, expires_at) VALUES (CAST(:u AS uuid), :k, :e, :h, :x)
                                ON CONFLICT DO NOTHING RETURNING key""", u=uid, k=key, e=request.url.path, h=h, x=datetime.now(timezone.utc) + timedelta(hours=48))
                if not ins:
                    ex = one(c, "SELECT * FROM idempotency_keys WHERE user_id = CAST(:u AS uuid) AND key = :k", u=uid, k=key)
            if not ins:
                if ex["request_hash"] != h:
                    return problem(422, "IDEMPOTENCY_KEY_REUSED", "This Idempotency-Key was used with a different request", request=request)
                if ex["response_status"] is None:
                    return problem(409, "REQUEST_IN_PROGRESS", "The original request is still being processed", request=request)
                return JSONResponse(ex["response_body"], status_code=ex["response_status"], headers={"Idempotent-Replay": "true"})
            try:
                resp = await original(request)
            except Exception:
                with tx() as c:
                    q(c, "DELETE FROM idempotency_keys WHERE user_id = CAST(:u AS uuid) AND key = :k", u=uid, k=key)
                raise
            with tx() as c:
                if 200 <= resp.status_code < 300:
                    try:
                        q(c, "UPDATE idempotency_keys SET response_status = :s, response_body = CAST(:b AS jsonb) WHERE user_id = CAST(:u AS uuid) AND key = :k",
                          s=resp.status_code, b=resp.body.decode() or "null", u=uid, k=key)
                    except Exception:
                        q(c, "DELETE FROM idempotency_keys WHERE user_id = CAST(:u AS uuid) AND key = :k", u=uid, k=key)
                else:       # failures are not replayed: the client may fix the problem and retry with the same key
                    q(c, "DELETE FROM idempotency_keys WHERE user_id = CAST(:u AS uuid) AND key = :k", u=uid, k=key)
            return resp

        return handler
