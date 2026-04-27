"""Env-based settings for the wk-2 single-tenant Splunk connection.

Wk-4 will add per-tenant lookup keyed by `tenant_id` against the encrypted
columns in `tenants` (Fernet-decrypted at request time). Wk-2 reads founder's
single connection from the env vars docker-compose injects.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SplunkSettings(BaseSettings):
    """Splunk REST + HEC connection params injected via env."""

    splunk_host: str = Field(..., description="Splunk management host (REST :8089).")
    splunk_port: int = Field(8089, description="Splunk management REST port.")
    splunk_token: str = Field(..., description="Service-account bearer token.")
    splunk_verify_tls: bool = Field(
        True,
        description=(
            "Verify TLS on the management endpoint. Disable only for self-signed "
            "lab Splunk; production must keep True."
        ),
    )

    splunk_hec_host: str = Field(
        "",
        description="HEC host (post-events to triage_verdicts index, wk 8).",
    )
    splunk_hec_port: int = Field(8088, description="HEC port.")
    splunk_hec_token: str = Field("", description="HEC token (wk 8).")

    model_config = SettingsConfigDict(env_file=None, case_sensitive=False, extra="ignore")
