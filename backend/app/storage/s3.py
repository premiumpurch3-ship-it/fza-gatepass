from typing import Iterator
from urllib.parse import quote

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from ..core.config import settings
from .base import StorageBackend


class S3Storage(StorageBackend):
    """MinIO (dev) / AWS S3 / any S3-compatible provider. Presigned URLs are signed against S3_PUBLIC_ENDPOINT (reachable by clients)."""

    def __init__(self):
        cfg = Config(signature_version="s3v4", s3={"addressing_style": "path" if settings.s3_force_path_style else "auto"})
        kw = dict(region_name=settings.s3_region, aws_access_key_id=settings.s3_access_key,
                  aws_secret_access_key=settings.s3_secret_key, config=cfg)
        self.bucket = settings.s3_bucket
        self.client = boto3.client("s3", endpoint_url=settings.s3_endpoint, **kw)
        self.signer = boto3.client("s3", endpoint_url=settings.s3_public_endpoint or settings.s3_endpoint, **kw)

    def presign_put(self, key, content_type, max_bytes, expires=900):
        url = self.signer.generate_presigned_url("put_object", Params={"Bucket": self.bucket, "Key": key, "ContentType": content_type},
                                                 ExpiresIn=expires)
        return {"url": url, "method": "PUT", "headers": {"Content-Type": content_type}}

    def presign_get(self, key, filename, content_type, inline, expires=60):
        disp = f"{'inline' if inline else 'attachment'}; filename*=UTF-8''{quote(filename)}"
        return self.signer.generate_presigned_url("get_object", Params={
            "Bucket": self.bucket, "Key": key, "ResponseContentDisposition": disp, "ResponseContentType": content_type}, ExpiresIn=expires)

    def head(self, key):
        try:
            r = self.client.head_object(Bucket=self.bucket, Key=key)
            return {"size": r["ContentLength"]}
        except ClientError:
            return None

    def get_range(self, key, start, end):
        return self.client.get_object(Bucket=self.bucket, Key=key, Range=f"bytes={start}-{end}")["Body"].read()

    def iter_bytes(self, key, chunk=1024 * 1024) -> Iterator[bytes]:
        body = self.client.get_object(Bucket=self.bucket, Key=key)["Body"]
        yield from body.iter_chunks(chunk)

    def put_bytes(self, key, data, content_type):
        self.client.put_object(Bucket=self.bucket, Key=key, Body=data, ContentType=content_type)

    def delete(self, key):
        self.client.delete_object(Bucket=self.bucket, Key=key)
