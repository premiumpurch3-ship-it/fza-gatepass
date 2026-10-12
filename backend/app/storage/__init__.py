from functools import lru_cache
from ..core.config import settings
from .base import StorageBackend


@lru_cache
def get_storage() -> StorageBackend:
    if settings.storage_backend == "s3":
        from .s3 import S3Storage
        return S3Storage()
    from .local import LocalStorage
    return LocalStorage(settings.local_storage_dir)
