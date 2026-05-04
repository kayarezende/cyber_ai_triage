"""Tests for the wk-9 audit chain Python verifier.

Cluster A (2026-05-04) added `hash_scope` to the digest in lockstep with the
plpgsql trigger; the helper now requires `hash_scope` as a kw-only no-default
argument so future drift fails loudly at every call site.

The pure-Python golden tests pin the digest formula against the trigger from
migration `e5f7a1b9c4d6_app_runtime_role_audit_hardening.py`:

    NEW.content_hash := encode(
      digest(
        COALESCE(NEW.hash_scope, '') || '|' ||
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
        hash_scope="investigation:00000000-0000-0000-0000-000000000010",
        tenant_id_text="00000000-0000-0000-0000-000000000001",
        investigation_id_text="00000000-0000-0000-0000-000000000010",
        actor="orchestrator:investigation",
        action="investigation_started",
        details_text='{"thread_id": "t-1"}',
        created_at_text="2026-04-27 12:00:00+00",
        previous_hash="",
    )
    payload = (
        "investigation:00000000-0000-0000-0000-000000000010|"
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
        hash_scope=None,
        tenant_id_text=None,
        investigation_id_text=None,
        actor=None,
        action=None,
        details_text=None,
        created_at_text=None,
        previous_hash=None,
    )
    assert digest == _expected("|||||||")


def test_hash_chains_through_previous_hash() -> None:
    first = compute_audit_row_hash(
        hash_scope="s",
        tenant_id_text="t",
        investigation_id_text="i",
        actor="a",
        action="x",
        details_text="{}",
        created_at_text="2026-04-27 12:00:00+00",
        previous_hash="",
    )
    second = compute_audit_row_hash(
        hash_scope="s",
        tenant_id_text="t",
        investigation_id_text="i",
        actor="a",
        action="y",
        details_text="{}",
        created_at_text="2026-04-27 12:00:01+00",
        previous_hash=first,
    )
    assert first != second
    assert len(second) == 64  # sha256 hex length


def test_hash_differs_when_only_scope_differs() -> None:
    """MED-6 protection: identical content in two different scopes must not
    collide. Without `hash_scope` in the digest, an attacker with row-write
    access could move a row between scopes silently."""
    base_kwargs = dict(
        tenant_id_text="t",
        investigation_id_text="i",
        actor="a",
        action="x",
        details_text="{}",
        created_at_text="2026-04-27 12:00:00+00",
        previous_hash="",
    )
    digest_a = compute_audit_row_hash(hash_scope="investigation:aaa", **base_kwargs)
    digest_b = compute_audit_row_hash(hash_scope="investigation:bbb", **base_kwargs)
    assert digest_a != digest_b


def _row(
    *,
    row_id: int,
    actor: str,
    action: str,
    details_text: str,
    created_at_text: str,
    previous_hash: str,
    hash_scope: str = "test:scope",
) -> dict[str, object]:
    digest = compute_audit_row_hash(
        hash_scope=hash_scope,
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
        "hash_scope": hash_scope,
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


def test_verify_chain_detects_scope_mismatch() -> None:
    """Cluster A MED-6: a row built under scope X but inserted with scope Y
    must verify as broken, because the digest binds scope."""
    row = _row(
        row_id=0,
        actor="a",
        action="x",
        details_text="{}",
        created_at_text="2026-04-27 12:00:00+00",
        previous_hash="",
        hash_scope="investigation:aaa",
    )
    # Pretend the row was moved into a different scope.
    row["hash_scope"] = "investigation:bbb"
    result = verify_chain([row])
    assert result.valid is False
    assert result.first_invalid_row_id == 0


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
    dsn = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL", "")
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
            cur.execute("""
                INSERT INTO audit_log
                    (tenant_id, investigation_id, actor, action, details, hash_scope)
                VALUES
                    ('00000000-0000-0000-0000-0000000000aa',
                     NULL,
                     'pytest:audit_chain',
                     'cluster_a_chain_check',
                     '{"k": "v"}'::jsonb,
                     'tenant:00000000-0000-0000-0000-0000000000aa')
                RETURNING id, tenant_id::text, investigation_id::text, actor, action,
                          details::text, created_at::text, previous_hash, content_hash,
                          hash_scope
                """)
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
                hash_scope,
            ) = row
        # Roll back the INSERT — audit_log triggers reject DELETE/UPDATE,
        # so we let the txn rollback (no commit). The test row never persists.
        conn.rollback()

    expected = compute_audit_row_hash(
        hash_scope=hash_scope,
        tenant_id_text=tenant_id_text,
        investigation_id_text=investigation_id_text,
        actor=actor,
        action=action,
        details_text=details_text,
        created_at_text=created_at_text,
        previous_hash=previous_hash,
    )
    assert expected == content_hash
