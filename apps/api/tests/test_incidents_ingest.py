"""Tests for POST /api/incidents/ingest."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

_VALID_NOTABLE: dict[str, Any] = {
    "_time": "1745795400",
    "search_name": "Access - Excessive Failed Logins - Rule",
    "signature": "47 failed logons within 60s from single source",
    "urgency": "medium",
    "src_ip": "203.0.113.55",
    "dest": "vpn-gw-01",
    "dest_ip": "10.0.0.5",
    "annotations": {"mitre_attack": ["T1110", "T1110.001"]},
    "rid": "ES-RULE-AUTH-002",
}


def test_ingest_rejects_bad_secret(client: TestClient, io_spies: dict[str, list[Any]]) -> None:
    response = client.post(
        "/api/incidents/ingest",
        json={"secret": "wrong", "result": _VALID_NOTABLE},
    )
    assert response.status_code == 401
    assert io_spies["uploads"] == []
    assert io_spies["audits"] == []
    assert io_spies["enqueues"] == []


def test_ingest_rejects_missing_secret_field(
    client: TestClient, io_spies: dict[str, list[Any]]
) -> None:
    # `secret` is required on IngestRequest → Pydantic 422.
    response = client.post(
        "/api/incidents/ingest",
        json={"result": _VALID_NOTABLE},
    )
    assert response.status_code == 422
    assert io_spies["uploads"] == []


def test_ingest_returns_503_when_server_secret_unset(
    monkeypatch: pytest.MonkeyPatch, io_spies: dict[str, list[Any]]
) -> None:
    """If INGEST_WEBHOOK_SECRET is empty, the endpoint refuses with 503."""
    monkeypatch.delenv("INGEST_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("DEV_BYPASS_AUTH", "1")

    from sentient_api.main import app

    client = TestClient(app)
    response = client.post(
        "/api/incidents/ingest",
        json={"secret": "anything", "result": _VALID_NOTABLE},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "ingest_secret_not_configured"


def test_ingest_rejects_malformed_notable(
    client: TestClient, io_spies: dict[str, list[Any]], webhook_secret: str
) -> None:
    """Notable missing required `_time` + `search_name` → 400."""
    response = client.post(
        "/api/incidents/ingest",
        json={"secret": webhook_secret, "result": {"missing": "everything"}},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "invalid_notable"
    # Raw payload is uploaded to MinIO BEFORE validation so we have the original
    # for forensics even when mapping fails. Confirm that path.
    assert len(io_spies["uploads"]) == 1
    # No DB / audit / enqueue side effects on a failed validation.
    assert io_spies["audits"] == []
    assert io_spies["enqueues"] == []


def test_ingest_rejects_unparseable_time(
    client: TestClient, io_spies: dict[str, list[Any]], webhook_secret: str
) -> None:
    bad_notable = {**_VALID_NOTABLE, "_time": "not-a-timestamp"}
    response = client.post(
        "/api/incidents/ingest",
        json={"secret": webhook_secret, "result": bad_notable},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "invalid_notable_time"
    assert io_spies["audits"] == []
    assert io_spies["enqueues"] == []


def test_ingest_happy_path_wrapped(
    client: TestClient, io_spies: dict[str, list[Any]], webhook_secret: str
) -> None:
    """Splunk's default wrapped payload shape: `{secret, result, ...}`."""
    response = client.post(
        "/api/incidents/ingest",
        json={
            "secret": webhook_secret,
            "search_name": "outer-wrapper-name-ignored",
            "sid": "scheduler__sid_001",
            "result": _VALID_NOTABLE,
        },
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert "incident_id" in body

    incident_id = body["incident_id"]
    # MinIO upload — raw notable, JSON-encoded, into the configured bucket.
    assert len(io_spies["uploads"]) == 1
    upload = io_spies["uploads"][0]
    assert upload["bucket"] == "evidence-test"
    assert upload["key"].endswith(f"{incident_id}.json")
    assert upload["content_type"] == "application/json"

    # One audit_log row for the ingest.
    assert len(io_spies["audits"]) == 1
    audit = io_spies["audits"][0]
    assert audit["actor"] == "webhook"
    assert audit["action"] == "incident_ingested"
    assert audit["investigation_id"] is None
    assert audit["details"]["siem_notable_id"] == "ES-RULE-AUTH-002"
    assert audit["details"]["ocsf_uid"] == incident_id

    # Redis enqueue — IngestJob with the new incident_id.
    assert len(io_spies["enqueues"]) == 1
    job = io_spies["enqueues"][0]
    assert str(job.incident_id) == incident_id
    assert job.trace_id  # uuid hex string


def test_ingest_happy_path_flat(
    client: TestClient, io_spies: dict[str, list[Any]], webhook_secret: str
) -> None:
    """Flat shape — convenient for curl smoke; no Splunk wrapper."""
    response = client.post(
        "/api/incidents/ingest",
        json={"secret": webhook_secret, **_VALID_NOTABLE},
    )
    assert response.status_code == 202
    assert len(io_spies["uploads"]) == 1
    assert len(io_spies["audits"]) == 1
    assert len(io_spies["enqueues"]) == 1


def test_ingest_storage_error_returns_502(
    monkeypatch: pytest.MonkeyPatch, configured_env: None, webhook_secret: str
) -> None:
    """If MinIO upload fails (e.g. bucket missing), we surface 502 — never 5xx fallthrough."""
    from sentient_common.storage import StorageError

    def boom(**_: Any) -> str:
        raise StorageError("MinIO bucket missing — run setup_minio.py")

    monkeypatch.setattr("sentient_api.routers.incidents.upload_evidence", boom)

    from sentient_api.main import app

    client = TestClient(app)
    response = client.post(
        "/api/incidents/ingest",
        json={"secret": webhook_secret, "result": _VALID_NOTABLE},
    )
    assert response.status_code == 502
    assert response.json()["detail"] == "evidence_upload_failed"
