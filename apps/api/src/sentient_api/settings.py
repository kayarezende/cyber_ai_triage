"""FastAPI settings loaded from the environment via pydantic-settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict

# Fixed UUID used for the dev-bypass user's tenant. Real tenants get real UUIDs
# from Postgres via gen_random_uuid() once the tenant-bootstrap flow lands.
DEV_TENANT_ID = "00000000-0000-0000-0000-000000000001"


class Settings(BaseSettings):
    """Environment-backed settings for the API service."""

    model_config = SettingsConfigDict(
        env_file=None,
        case_sensitive=False,
        extra="ignore",
    )

    dev_bypass_auth: bool = False
    dev_user_email: str = "dev@sentientlayer.ai"
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/sentient"

    # Wk-4 ingest webhook + queue + evidence store.
    ingest_webhook_secret: str = ""
    redis_url: str = "redis://localhost:6379/0"
    minio_endpoint: str = "http://localhost:9000"
    minio_root_user: str = "minioadmin"
    minio_root_password: str = "minioadmin"
    minio_bucket_evidence: str = "evidence"


def get_settings() -> Settings:
    """Construct a fresh Settings each call so tests can monkeypatch env vars."""
    return Settings()
