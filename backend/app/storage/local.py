import os
import re
import time
from pathlib import Path
from typing import Iterator

import jwt

from ..core.config import settings
from .base import StorageBackend


class LocalStorage(StorageBackend):
    """Filesystem implementation of the same interface; presigned URLs point to the API (/api/v1/storage/local/<token>)."""

    def __init__(self, root: str):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", key) or ".." in key:
            raise ValueError("bad storage key")
        p = (self.root / key).resolve()
        if self.root not in p.parents:
            raise ValueError("bad storage key")
        return p

    def _token(self, method: str, key: str, expires: int, **extra) -> str:
        return jwt.encode({"m": method, "k": key, "exp": int(time.time()) + expires, **extra}, settings.secret_key, algorithm="HS256")

    def presign_put(self, key, content_type, max_bytes, expires=900):
        t = self._token("PUT", key, expires, ct=content_type, mx=max_bytes)
        return {"url": f"{settings.public_base_url}/api/v1/storage/local/{t}", "method": "PUT", "headers": {"Content-Type": content_type}}

    def presign_get(self, key, filename, content_type, inline, expires=60):
        t = self._token("GET", key, expires, fn=filename, ct=content_type, il=inline)
        return f"{settings.public_base_url}/api/v1/storage/local/{t}"

    def head(self, key):
        p = self._path(key)
        return {"size": p.stat().st_size} if p.exists() else None

    def get_range(self, key, start, end):
        with open(self._path(key), "rb") as f:
            f.seek(start)
            return f.read(end - start + 1)

    def iter_bytes(self, key, chunk=1024 * 1024) -> Iterator[bytes]:
        with open(self._path(key), "rb") as f:
            while b := f.read(chunk):
                yield b

    def put_bytes(self, key, data, content_type):
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def delete(self, key):
        p = self._path(key)
        if p.exists():
            os.remove(p)
