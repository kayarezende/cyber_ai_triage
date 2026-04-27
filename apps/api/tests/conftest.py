"""Shared pytest fixtures for apps/api tests.

Provides a FastAPI TestClient with the wk-4 IO surface mocked at the
router-module level (storage, DB session, audit, enqueue). Tests assert on
captured calls without needing a live Postgres / Redis / MinIO.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def webhook_secret() -> str:
    return "test-webhook-secret-very-long-string"


@pytest.fixture
def configured_env(
    monkeypatch: pytest.MonkeyPatch, webhook_secret: str
) -> None:
    """Set the env vars the API needs at import + request time."""
    monkeypatch.setenv("INGEST_WEBHOOK_SECRET", webhook_secret)
    monkeypatch.setenv("DEV_BYPASS_AUTH", "1")
    monkeypatch.setenv("MINIO_BUCKET_EVIDENCE", "evidence-test")


@pytest.fixture
def io_spies(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Patch the IO helpers inside the incidents router with capture-only spies.

    Tests inspect the returned dict to verify the webhook produced the right
    side effects without needing real Postgres / Redis / MinIO.
    """
    uploads: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    enqueues: list[Any] = []
    db_executes: list[tuple[str, dict[str, Any]]] = []

    def fake_upload(*, bucket: str, key: str, body: bytes, content_type: str) -> str:
        uploads.append(
            {"bucket": bucket, "key": key, "body": body, "content_type": content_type}
        )
        return key

    @contextmanager
    def fake_session(tenant_id: Any) -> Iterator[MagicMock]:
        conn = MagicMock(name=f"conn[{tenant_id}]")

        def capture_execute(stmt: Any, params: dict[str, Any] | None = None) -> Any:
            db_executes.append((str(stmt), params or {}))
            return MagicMock()

        conn.execute.side_effect = capture_execute
        yield conn

    def fake_audit(
        conn: Any,
        *,
        tenant_id: Any,
        investigation_id: Any,
        actor: str,
        action: str,
        details: dict[str, Any],
    ) -> None:
        audits.append(
            {
                "tenant_id": str(tenant_id),
                "investigation_id": str(investigation_id) if investigation_id else None,
                "actor": actor,
                "action": action,
                "details": details,
            }
        )

    def fake_enqueue(_client: Any, job: Any) -> None:
        enqueues.append(job)

    fake_redis_factory = MagicMock(return_value=MagicMock(name="redis-stub"))

    monkeypatch.setattr(
        "sentient_api.routers.incidents.upload_evidence", fake_upload
    )
    monkeypatch.setattr(
        "sentient_api.routers.incidents.tenant_session", fake_session
    )
    monkeypatch.setattr(
        "sentient_api.routers.incidents.insert_audit_log", fake_audit
    )
    monkeypatch.setattr(
        "sentient_api.routers.incidents.enqueue_investigation", fake_enqueue
    )
    monkeypatch.setattr(
        "sentient_api.routers.incidents.redis_lib.Redis.from_url",
        fake_redis_factory,
    )

    return {
        "uploads": uploads,
        "audits": audits,
        "enqueues": enqueues,
        "db_executes": db_executes,
    }


@pytest.fixture
def client(configured_env: None) -> TestClient:
    # Import after env is configured so Settings sees the env vars.
    from sentient_api.main import app

    return TestClient(app)
