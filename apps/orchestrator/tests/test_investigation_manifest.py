"""Wk-7 fix #6 — direct unit tests for runner._try_upload_manifest.

Existing `test_investigation_runner.py` autouse-patches the manifest path
to a no-op, so its body had zero direct coverage. This file exercises the
three branches:

  * happy path: build → upload → UPDATE evidence_s3_key → emit `manifest_uploaded`
  * MinIO failure: upload raises → emit `manifest_upload_failed`, no UPDATE,
    function returns without raising
  * double failure: upload raises AND the audit-emit session also raises →
    function still returns

The runner's verdict-finalize path is not exercised here; `_try_upload_manifest`
runs AFTER `_finalize_done` commits, so the contract is "do not raise, no
matter what." That contract is the load-bearing invariant tested below.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from sentient_common.storage import StorageError
from sentient_ocsf.detection_finding import (
    Analytic,
    DetectionFinding,
    FindingInfo,
    Metadata,
    Product,
)
from sentient_orchestrator.investigation import runner as runner_mod
from sentient_orchestrator.investigation.runner import _try_upload_manifest
from sentient_orchestrator.investigation.state import InvestigationOutput

TENANT = UUID("11111111-1111-1111-1111-111111111111")
INC = UUID("22222222-2222-2222-2222-222222222222")
INV = UUID("33333333-3333-3333-3333-333333333333")


def _finding() -> DetectionFinding:
    return DetectionFinding(
        category_uid=2,
        class_uid=2004,
        activity_id=1,
        type_uid=200401,
        severity_id=4,
        time=1700000000000,
        metadata=Metadata(
            version="1.3.0",
            log_provider="splunk",
            product=Product(name="Splunk", vendor_name="Splunk Inc."),
        ),
        finding_info=FindingInfo(
            uid="fid-manifest-test",
            title="Manifest test",
            analytic=Analytic(name="t", type_id=2, uid="a", version="1"),
        ),
        mitre_techniques=[],
        attacks=[],
    )


def _verdict() -> InvestigationOutput:
    return InvestigationOutput(
        verdict="true_positive",
        confidence=85,
        severity="high",
        mitre_techniques=["T1059.001"],
        summary="Confirmed C2.",
        evidence=["spl: search"],
        reasoning="r",
    )


class _FakeConn:
    """Records execute() calls for assertion."""

    def __init__(self) -> None:
        self.executes: list[tuple[str, dict[str, Any]]] = []

    def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = str(getattr(stmt, "text", stmt))
        self.executes.append((sql, params or {}))
        return MagicMock()


@pytest.fixture
def patch_session(monkeypatch: pytest.MonkeyPatch) -> list[_FakeConn]:
    """Each tenant_session() use gets a fresh _FakeConn; we collect them."""
    conns: list[_FakeConn] = []

    @contextmanager
    def session(_tid: UUID) -> Any:
        conn = _FakeConn()
        conns.append(conn)
        yield conn

    monkeypatch.setattr(runner_mod, "tenant_session", session)
    return conns


@pytest.fixture
def emit_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    def _track(name: str) -> Any:
        def _f(_conn: object, **kwargs: Any) -> None:
            calls.append((name, kwargs))

        return _f

    monkeypatch.setattr(runner_mod, "emit_manifest_uploaded", _track("uploaded"))
    monkeypatch.setattr(runner_mod, "emit_manifest_upload_failed", _track("upload_failed"))
    return calls


@pytest.fixture(autouse=True)
def patch_build(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """build_evidence_manifest returns canned dict; capture invocation."""
    captured: dict[str, Any] = {"calls": 0, "last_kwargs": None}

    def _build(**kwargs: Any) -> dict[str, Any]:
        captured["calls"] += 1
        captured["last_kwargs"] = kwargs
        return {"investigation_id": str(INV), "schema_version": 1}

    monkeypatch.setattr(runner_mod, "build_evidence_manifest", _build)
    return captured


# ----------------------------------------------------------- happy path


def test_happy_path_updates_evidence_s3_key_and_emits_uploaded(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: list[_FakeConn],
    emit_calls: list[tuple[str, dict[str, Any]]],
) -> None:
    upload_kwargs: dict[str, Any] = {}

    def fake_upload(**kwargs: Any) -> tuple[str, str, int]:
        upload_kwargs.update(kwargs)
        return ("evidence", f"manifests/{TENANT}/{INV}.json", 1024)

    monkeypatch.setattr(runner_mod, "upload_manifest", fake_upload)

    _try_upload_manifest(
        tenant_id=TENANT,
        investigation_id=INV,
        incident_id=INC,
        finding=_finding(),
        final_state={},  # type: ignore[arg-type]
        verdict=_verdict(),
        review=None,
    )

    # Two tenant_session uses: one for build, one for UPDATE + audit.
    assert len(patch_session) == 2
    update_conn = patch_session[1]
    assert any(
        "UPDATE investigations SET evidence_s3_key" in sql for sql, _ in update_conn.executes
    )
    # Wk-7 round-2 R-4: real assertion that fake_upload was actually invoked
    # (the previous `or True` made this line a no-op).
    assert upload_kwargs, "fake_upload was not invoked"
    assert upload_kwargs["tenant_id"] == TENANT
    assert upload_kwargs["investigation_id"] == INV
    uploaded = [k for n, k in emit_calls if n == "uploaded"]
    assert uploaded, emit_calls
    assert uploaded[0]["bucket"] == "evidence"
    assert uploaded[0]["key"] == f"manifests/{TENANT}/{INV}.json"
    assert uploaded[0]["size_bytes"] == 1024
    failed = [k for n, k in emit_calls if n == "upload_failed"]
    assert failed == []


# ----------------------------------------------------------- MinIO failure


def test_minio_failure_emits_upload_failed_no_raise(
    monkeypatch: pytest.MonkeyPatch,
    patch_session: list[_FakeConn],
    emit_calls: list[tuple[str, dict[str, Any]]],
) -> None:
    def fake_upload(**_kwargs: Any) -> tuple[str, str, int]:
        msg = "MinIO down: connection refused"
        raise StorageError(msg)

    monkeypatch.setattr(runner_mod, "upload_manifest", fake_upload)

    # Must not raise.
    _try_upload_manifest(
        tenant_id=TENANT,
        investigation_id=INV,
        incident_id=INC,
        finding=_finding(),
        final_state={},  # type: ignore[arg-type]
        verdict=_verdict(),
        review=None,
    )

    failed = [k for n, k in emit_calls if n == "upload_failed"]
    assert failed
    assert failed[0]["error_type"] == "StorageError"
    assert "MinIO down" in failed[0]["error_message"]
    # No evidence_s3_key UPDATE happened.
    update_seen = any(
        "UPDATE investigations SET evidence_s3_key" in sql
        for conn in patch_session
        for sql, _ in conn.executes
    )
    assert update_seen is False
    # `manifest_uploaded` audit must NOT have fired.
    uploaded = [k for n, k in emit_calls if n == "uploaded"]
    assert uploaded == []


# ----------------------------------------------------------- double failure


def test_double_failure_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """upload_manifest raises AND the failure-emit session also raises.
    Function must still return without propagating."""

    def fake_upload(**_kwargs: Any) -> tuple[str, str, int]:
        msg = "MinIO down"
        raise StorageError(msg)

    @contextmanager
    def broken_session(_tid: UUID) -> Any:
        msg = "DB pool exhausted"
        raise RuntimeError(msg)
        yield  # unreachable, satisfies generator protocol

    monkeypatch.setattr(runner_mod, "upload_manifest", fake_upload)
    monkeypatch.setattr(runner_mod, "tenant_session", broken_session)

    # Must not raise — outer contract is "best-effort, never propagate".
    _try_upload_manifest(
        tenant_id=TENANT,
        investigation_id=INV,
        incident_id=INC,
        finding=_finding(),
        final_state={},  # type: ignore[arg-type]
        verdict=_verdict(),
        review=None,
    )
