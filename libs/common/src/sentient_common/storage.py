"""MinIO upload helper for evidence artifacts.

Wk-4 caller is the ingest webhook (raw Splunk payload). Wk-7+ adds the
investigation evidence manifest. Object Lock + versioning are enabled at
bucket creation time (`db/seeds/setup_minio.py`) per ADR-0017 — this module
does not touch bucket config.

Reads MinIO client config from env (matches `db/seeds/setup_minio.py`):
    MINIO_ENDPOINT       (default `http://localhost:9000`)
    MINIO_ROOT_USER      (default `minioadmin`)
    MINIO_ROOT_PASSWORD  (default `minioadmin`)
"""

from __future__ import annotations

import io
import os
import threading
from functools import lru_cache

from minio import Minio
from minio.error import S3Error


class StorageError(RuntimeError):
    """Wrapper for MinIO errors so callers don't have to import minio."""


_client_lock = threading.Lock()


@lru_cache(maxsize=1)
def _client() -> Minio:
    endpoint = os.environ.get("MINIO_ENDPOINT", "http://localhost:9000")
    secure = endpoint.startswith("https://")
    host = endpoint.removeprefix("https://").removeprefix("http://")
    return Minio(
        host,
        access_key=os.environ.get("MINIO_ROOT_USER", "minioadmin"),
        secret_key=os.environ.get("MINIO_ROOT_PASSWORD", "minioadmin"),
        secure=secure,
    )


def upload_evidence(
    *,
    bucket: str,
    key: str,
    body: bytes,
    content_type: str = "application/json",
) -> str:
    """Upload bytes to MinIO. Returns key on success.

    Raises StorageError on bucket-missing (`NoSuchBucket` — likely setup_minio.py
    was skipped) or any other S3 error.
    """
    with _client_lock:
        client = _client()
    try:
        client.put_object(
            bucket_name=bucket,
            object_name=key,
            data=io.BytesIO(body),
            length=len(body),
            content_type=content_type,
        )
    except S3Error as exc:
        if exc.code == "NoSuchBucket":
            msg = (
                f"MinIO bucket {bucket!r} does not exist. "
                "Run `python db/seeds/setup_minio.py` before sending traffic."
            )
            raise StorageError(msg) from exc
        msg = f"MinIO upload failed: {exc.code}: {exc.message}"
        raise StorageError(msg) from exc
    return key


__all__ = ["StorageError", "upload_evidence"]
