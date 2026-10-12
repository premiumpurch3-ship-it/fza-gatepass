"""Thin SQL layer: SQLAlchemy Core + text(). All business writes go through `tx()` (one transaction)."""
import json
import uuid
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import create_engine, text

from .config import settings

engine = create_engine(settings.database_url, pool_size=10, max_overflow=10, pool_pre_ping=True, future=True)


def jsonable(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Decimal):
        return str(o)
    if isinstance(o, uuid.UUID):
        return str(o)
    if isinstance(o, (bytes, memoryview)):
        return bytes(o).hex()
    raise TypeError(f"not serializable: {type(o)}")


def J(obj) -> str | None:
    return None if obj is None else json.dumps(obj, default=jsonable, sort_keys=True)


@contextmanager
def tx():
    with engine.begin() as c:
        yield c


def q(c, sql: str, /, **p):
    return c.execute(text(sql), p)


def one(c, sql: str, /, **p):
    r = q(c, sql, **p).mappings().first()
    return dict(r) if r else None


def rows(c, sql: str, /, **p):
    return [dict(r) for r in q(c, sql, **p).mappings().all()]


def scalar(c, sql: str, /, **p):
    return q(c, sql, **p).scalar()


def new_id() -> str:
    return str(uuid.uuid4())
