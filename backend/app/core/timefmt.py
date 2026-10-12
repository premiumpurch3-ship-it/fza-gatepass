from datetime import date, datetime
from zoneinfo import ZoneInfo
from .config import settings

TZ = ZoneInfo(settings.timezone)


def fmt_dt(v) -> str:
    if not v:
        return ""
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    if isinstance(v, date) and not isinstance(v, datetime):
        return v.strftime("%d-%b-%Y")
    return v.astimezone(TZ).strftime("%d-%b-%Y %I:%M %p")


def fmt_d(v) -> str:
    if not v:
        return ""
    if isinstance(v, datetime):
        v = v.astimezone(TZ).date()
    return v.strftime("%d-%b-%Y")
