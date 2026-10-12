import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.fernet import Fernet

from .config import settings
from .errors import Invalid

_ph = PasswordHasher(time_cost=settings.argon2_time_cost, memory_cost=settings.argon2_memory_kib)
COMMON = {"password", "password1", "12345678", "123456789", "1234567890", "qwerty123", "letmein123", "admin12345", "welcome123"}


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, h: str) -> bool:
    try:
        return _ph.verify(h, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def check_password_policy(pw: str, min_len: int = 10, username: str | None = None):
    if len(pw) < min_len:
        raise Invalid(f"Password must be at least {min_len} characters", "WEAK_PASSWORD")
    if pw.lower() in COMMON or (username and username.lower() in pw.lower()):
        raise Invalid("Password is too common or contains the username", "WEAK_PASSWORD")
    if not (any(c.isalpha() for c in pw) and any(c.isdigit() for c in pw)):
        raise Invalid("Password must contain letters and digits", "WEAK_PASSWORD")


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def make_access_token(user_id: str, session_id: str, scope: str = "full", minutes: int | None = None) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=minutes or (settings.setup_token_minutes if scope != "full" else settings.access_token_minutes))
    return jwt.encode({"sub": user_id, "sid": session_id, "jti": str(uuid.uuid4()), "scp": scope,
                       "iat": int(now.timestamp()), "exp": int(exp.timestamp())}, settings.secret_key, algorithm="HS256")


def decode_access_token(tok: str) -> dict:
    return jwt.decode(tok, settings.secret_key, algorithms=["HS256"], options={"require": ["exp", "sub", "sid"]})


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.app_encryption_key.encode()).digest())
    return Fernet(key)


def encrypt_secret(s: str) -> str:
    return _fernet().encrypt(s.encode()).decode()


def decrypt_secret(s: str) -> str:
    return _fernet().decrypt(s.encode()).decode()


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="FZA-GatePass-MTJ")


def verify_totp(secret: str, code: str) -> bool:
    return bool(code) and pyotp.TOTP(secret).verify(code.strip(), valid_window=1)


def new_recovery_codes(n: int = 8) -> list[str]:
    return [secrets.token_hex(4) + "-" + secrets.token_hex(4) for _ in range(n)]
