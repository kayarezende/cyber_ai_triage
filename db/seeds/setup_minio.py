"""Create MinIO evidence bucket with Object Lock + versioning enabled.

Object Lock prevents object deletion even with bucket admin credentials. **Cannot
be enabled retroactively** — must be set at bucket creation time. Per ADR-0017.

Idempotent: detects if the bucket already exists; if so, asserts that Object Lock
is enabled (raise otherwise — that's a state mismatch we want to know about).

Reads MinIO config from env (see `.env.example`):
    MINIO_ENDPOINT (default `http://localhost:9000`)
    MINIO_ROOT_USER (default `minioadmin`)
    MINIO_ROOT_PASSWORD (default `minioadmin`)
    MINIO_BUCKET_EVIDENCE (default `evidence`)

Run after `docker compose up -d minio` is healthy. Or include in the bring-up
runbook alongside `setup_checkpointer.py`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from minio import Minio
from minio.commonconfig import ENABLED
from minio.versioningconfig import VersioningConfig


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _client() -> Minio:
    _load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    endpoint = os.environ.get("MINIO_ENDPOINT", "http://localhost:9000")
    # Minio() takes host:port + secure flag, not the scheme-prefixed URL.
    secure = endpoint.startswith("https://")
    host = endpoint.removeprefix("https://").removeprefix("http://")
    return Minio(
        host,
        access_key=os.environ.get("MINIO_ROOT_USER", "minioadmin"),
        secret_key=os.environ.get("MINIO_ROOT_PASSWORD", "minioadmin"),
        secure=secure,
    )


def main() -> int:
    bucket = os.environ.get("MINIO_BUCKET_EVIDENCE", "evidence")
    client = _client()

    if client.bucket_exists(bucket):
        # Validate Object Lock is enabled. If not, that's a config drift we want to surface.
        try:
            cfg = client.get_object_lock_config(bucket)
        except Exception as exc:  # noqa: BLE001 — minio raises a generic S3Error
            print(
                f"ERROR: bucket {bucket!r} exists but does not have Object Lock enabled. "
                "Object Lock cannot be enabled on an existing bucket — recreate the bucket "
                f"to fix this. ({exc})",
                file=sys.stderr,
            )
            return 1
        print(f"bucket {bucket!r} already exists with Object Lock (mode={cfg.mode}). ok.")
        return 0

    client.make_bucket(bucket, object_lock=True)
    client.set_bucket_versioning(bucket, VersioningConfig(ENABLED))
    print(f"bucket {bucket!r} created with Object Lock + versioning enabled.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
