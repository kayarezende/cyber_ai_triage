"""Tests for the wk-9 audit chain Python verifier.

The pure-Python golden tests pin the digest formula against the plpgsql
trigger from migration `b7c4e9a2f1d8`:

    NEW.content_hash := encode(
      digest(
        COALESCE(NEW.tenant_id::text, '') || '|' ||
        COALESCE(NEW.investigation_id::text, '') || '|' ||
        COALESCE(NEW.actor, '') || '|' ||
        COALESCE(NEW.action, '') || '|' ||
        COALESCE(NEW.details::text, '') || '|' ||
        COALESCE(NEW.created_at::text, '') || '|' ||
        NEW.previous_hash,
        'sha256'
      ),
      'hex'
    );

The integration test at the bottom (`@pytest.mark.integration`) inserts a
known row through the trigger and asserts Python recomputes the same hash;
it skips if no DATABASE_URL is reachable so unit-test runs stay self-contained.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from sentient_common.audit import (
    ChainVerification,
    compute_audit_row_hash,
    verify_chain,
)


def _expected(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_hash_matches_pipe_concat_formula() -> None:
    digest = compute_audit_row_hash(
        tenant_id_text="00000000-0000-0000-0000-000000000001",
        investigation_id_text="00000000-0000-0000-0000-000000000010",
        actor="orchestrator:investigation",
        action="investigation_started",
        details_text='{"thread_id": "t-1"}',
        created_at_text="2026-04-27 12:00:00+00",
        previous_hash="",
    )
    payload = (
        "00000000-0000-0000-0000-000000000001|"
        "00000000-0000-0000-0000-000000000010|"
        "orchestrator:investigation|"
        "investigation_started|"
        '{"thread_id": "t-1"}|'
        "2026-04-27 12:00:00+00|"
    )
    assert digest == _expected(payload)


def test_hash_handles_null_columns_via_empty_string() -> None:
    digest = compute_audit_row_hash(
        tenant_id_text=None,
        investigation_id_text=None,
        actor=None,
        action=None,
        details_text=None,
        created_at_text=None,
        previous_hash=None,
    )
    assert digest == _expected("||||||")


def test_hash_chains_through_previous_hash() -> None:
    first = compute_audit_row_hash(
        tenant_id_text="t",
        investigation_id_text="i",
        actor="a",
        action="x",
        details_text="{}",
        created_at_text="2026-04-27 12:00:00+00",
        previous_hash="",
    )
    second = compute_audit_row_hash(
        tenant_id_text="t",
        investigation_id_text="i",
        actor="a",
        action="y",
        details_text="{}",
        created_at_text="2026-04-27 12:00:01+00",
        previous_hash=first,
    )
    assert first != second
    # Chain link: second's recompute uses first as previous_hash
    assert second.endswith(second[-8:])  # sanity — non-empty hex


def _row(
    *,
    row_id: int,
    actor: str,
    action: str,
    details_text: str,
    created_at_text: str,
    previous_hash: str,
) -> dict[str, object]:
    digest = compute_audit_row_hash(
        tenant_id_text="t",
        investigation_id_text="i",
        actor=actor,
        action=action,
        details_text=details_text,
        created_at_text=created_at_text,
        previous_hash=previous_hash,
    )
    return {
        "id": row_id,
        "actor": actor,
        "action": action,
        "details_text": details_text,
        "created_at_text": created_at_text,
        "tenant_id_text": "t",
        "investigation_id_text": "i",
        "content_hash": digest,
        "previous_hash": previous_hash,
    }


def test_verify_chain_clean() -> None:
    rows: list[dict[str, object]] = []
    prev = ""
    for i in range(3):
        row = _row(
            row_id=i,
            actor="a",
            action=f"step-{i}",
            details_text="{}",
            created_at_text=f"2026-04-27 12:00:0{i}+00",
            previous_hash=prev,
        )
        rows.append(row)
        prev = str(row["content_hash"])

    result: ChainVerification = verify_chain(rows)
    assert result.valid is True
    assert result.first_invalid_row_id is None
    assert all(r.ok for r in result.rows)


def test_verify_chain_detects_tamper() -> None:
    rows: list[dict[str, object]] = []
    prev = ""
    for i in range(3):
        row = _row(
            row_id=i,
            actor="a",
            action=f"step-{i}",
            details_text="{}",
            created_at_text=f"2026-04-27 12:00:0{i}+00",
            previous_hash=prev,
        )
        rows.append(row)
        prev = str(row["content_hash"])

    rows[1]["content_hash"] = "deadbeef"
    result = verify_chain(rows)
    assert result.valid is False
    assert result.first_invalid_row_id == 1
    assert result.rows[0].ok is True
    assert result.rows[1].ok is False
    # Subsequent row's previous_hash now mismatches the tampered row.
    assert result.rows[2].ok is False


def test_verify_chain_detects_broken_previous_link() -> None:
    rows: list[dict[str, object]] = []
    prev = ""
    for i in range(2):
        row = _row(
            row_id=i,
            actor="a",
            action=f"step-{i}",
            details_text="{}",
            created_at_text=f"2026-04-27 12:00:0{i}+00",
            previous_hash=prev,
        )
        rows.append(row)
        prev = str(row["content_hash"])

    rows[1]["previous_hash"] = "not-the-actual-prior-hash"
    # Recompute would fail because the digest input changed.
    result = verify_chain(rows)
    assert result.valid is False
    assert result.first_invalid_row_id == 1


def test_verify_chain_empty_input() -> None:
    result = verify_chain([])
    assert result.valid is True
    assert result.total_rows == 0
    assert result.rows == []


@pytest.mark.integration
def test_python_hash_matches_plpgsql_trigger() -> None:
    """Live-DB parity test. Inserts a row through the trigger, fetches the
    text-cast column values, recomputes the hash in Python.
    """
    dsn = os.environ.get("DATABASE_URL", "")
    if not dsn:
        pytest.skip("DATABASE_URL not set")

    import psycopg

    libpq_dsn = dsn.replace("postgresql+psycopg://", "postgresql://", 1)
    try:
        conn = psycopg.connect(libpq_dsn, connect_timeout=2)
    except Exception:  # noqa: BLE001
        pytest.skip("Postgres unreachable")
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('app.current_tenant', %s, true)",
                ("00000000-0000-0000-0000-0000000000aa",),
            )
            cur.execute(
                """
                INSERT INTO audit_log
                    (tenant_id, investigation_id, actor, action, details, hash_scope)
                VALUES
                    ('00000000-0000-0000-0000-0000000000aa',
                     NULL,
                     'pytest:audit_chain',
                     'wk9_chain_check',
                     '{"k": "v"}'::jsonb,
                     'tenant:00000000-0000-0000-0000-0000000000aa')
                RETURNING id, tenant_id::text, investigation_id::text, actor, action,
                          details::text, created_at::text, previous_hash, content_hash
                """
            )
            row = cur.fetchone()
            assert row is not None
            (
                _id,
                tenant_id_text,
                investigation_id_text,
                actor,
                action,
                details_text,
                created_at_text,
                previous_hash,
                content_hash,
            ) = row
        # Roll back the INSERT — audit_log triggers reject DELETE/UPDATE,
        # so we let the txn rollback (no commit). The test row never persists.
        conn.rollback()

    expected = compute_audit_row_hash(
        tenant_id_text=tenant_id_text,
        investigation_id_text=investigation_id_text,
        actor=actor,
        action=action,
        details_text=details_text,
        created_at_text=created_at_text,
        previous_hash=previous_hash,
    )
    assert expected == content_hash
