"""Cluster A (CRIT-4 + MED-6): live-DB concurrency + scope-bind tests.

CRIT-4 — without `pg_advisory_xact_lock` in `compute_audit_hash()`, two
concurrent INSERTs into the same `hash_scope` could read the same
`prev_hash` and emit two rows pointing back to the same parent — a forked
chain that `verify_chain` would correctly reject. The migration adds the
lock; this test fires N parallel inserts and asserts the resulting chain
is straight (each row's `previous_hash` is the prior row's `content_hash`).

MED-6 — ALSO covered: a row whose `hash_scope` is mutated post-insert
must verify as broken because the digest binds scope. The unit-level
parity test for this lives in `libs/common/tests/test_audit_chain.py`;
the live-DB version here exercises the actual trigger.

Skipped when `MIGRATION_DATABASE_URL` (or `DATABASE_URL` superuser fallback)
isn't set so unit-only CI runs stay self-contained.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import Iterator

import pytest

from sentient_common.audit import compute_audit_row_hash, verify_chain

psycopg = pytest.importorskip("psycopg")


def _superuser_dsn() -> str:
    dsn = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("MIGRATION_DATABASE_URL / DATABASE_URL not set")
    return dsn.replace("postgresql+psycopg://", "postgresql://", 1)


TENANT = uuid.UUID("cccc0000-0000-0000-0000-000000000003")


@pytest.fixture
def seeded_tenant() -> Iterator[uuid.UUID]:
    dsn = _superuser_dsn()
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) " "ON CONFLICT (id) DO NOTHING",
            (str(TENANT), "Cluster-A concurrency test"),
        )
    try:
        yield TENANT
    finally:
        # audit_log triggers reject DELETE — we use a unique hash_scope per
        # test run instead of cleaning up rows. The tenant row itself stays
        # too (cheap, idempotent ON CONFLICT).
        pass


def _insert_one(dsn: str, tenant: uuid.UUID, scope: str, action: str) -> None:
    """Open a fresh connection + transaction per worker so the advisory
    lock actually sees concurrency. Pooled connections wouldn't serialize
    under SQLAlchemy txn boundaries."""
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('app.current_tenant', %s, true)",
                (str(tenant),),
            )
            cur.execute(
                """
                INSERT INTO audit_log
                    (tenant_id, investigation_id, actor, action, details, hash_scope)
                VALUES
                    (%s, NULL, 'pytest:concurrency', %s,
                     ('{"i": "' || %s || '"}')::jsonb, %s)
                """,
                (str(tenant), action, action, scope),
            )
        conn.commit()


@pytest.mark.integration
def test_concurrent_inserts_keep_chain_unbroken(
    seeded_tenant: uuid.UUID,
) -> None:
    """5 concurrent inserts must serialize via pg_advisory_xact_lock so the
    resulting chain has no fork (each row's previous_hash == prior row's
    content_hash)."""
    tenant = seeded_tenant
    dsn = _superuser_dsn()
    scope = f"investigation:{uuid.uuid4()}"

    async def _drive() -> None:
        await asyncio.gather(
            *[asyncio.to_thread(_insert_one, dsn, tenant, scope, f"step-{i}") for i in range(5)]
        )

    asyncio.run(_drive())

    # Fetch + verify.
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)",
            (str(tenant),),
        )
        cur.execute(
            """
            SELECT id, hash_scope, content_hash, previous_hash,
                   tenant_id::text, investigation_id::text, actor, action,
                   details::text, created_at::text
              FROM audit_log
             WHERE hash_scope = %s
             ORDER BY id ASC
            """,
            (scope,),
        )
        rows = [
            {
                "id": r[0],
                "hash_scope": r[1],
                "content_hash": r[2],
                "previous_hash": r[3],
                "tenant_id_text": r[4],
                "investigation_id_text": r[5],
                "actor": r[6],
                "action": r[7],
                "details_text": r[8],
                "created_at_text": r[9],
            }
            for r in cur.fetchall()
        ]
    assert len(rows) == 5

    result = verify_chain(rows)
    assert result.valid is True, f"chain verification failed at row {result.first_invalid_row_id}"
    # Sanity: previous_hash links from row N to row N-1 are intact.
    for prior, curr in zip(rows, rows[1:], strict=False):
        assert curr["previous_hash"] == prior["content_hash"]


@pytest.mark.integration
def test_cross_scope_row_substitution_detected(
    seeded_tenant: uuid.UUID,
) -> None:
    """MED-6 live: a row inserted under scope A, then 'moved' to scope B by
    re-reading with the wrong scope label, must fail verification because
    the digest binds scope."""
    tenant = seeded_tenant
    dsn = _superuser_dsn()
    scope_a = f"investigation:{uuid.uuid4()}"

    _insert_one(dsn, tenant, scope_a, "lone-row")

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)",
            (str(tenant),),
        )
        cur.execute(
            """
            SELECT id, hash_scope, content_hash, previous_hash,
                   tenant_id::text, investigation_id::text, actor, action,
                   details::text, created_at::text
              FROM audit_log
             WHERE hash_scope = %s
             ORDER BY id ASC
            """,
            (scope_a,),
        )
        rows = [
            {
                "id": r[0],
                "hash_scope": r[1],
                "content_hash": r[2],
                "previous_hash": r[3],
                "tenant_id_text": r[4],
                "investigation_id_text": r[5],
                "actor": r[6],
                "action": r[7],
                "details_text": r[8],
                "created_at_text": r[9],
            }
            for r in cur.fetchall()
        ]
    assert len(rows) >= 1

    # Sanity: the row verifies under its real scope.
    legit = compute_audit_row_hash(
        hash_scope=rows[-1]["hash_scope"],
        tenant_id_text=rows[-1]["tenant_id_text"],
        investigation_id_text=rows[-1]["investigation_id_text"],
        actor=rows[-1]["actor"],
        action=rows[-1]["action"],
        details_text=rows[-1]["details_text"],
        created_at_text=rows[-1]["created_at_text"],
        previous_hash=rows[-1]["previous_hash"] or "",
    )
    assert legit == rows[-1]["content_hash"]

    # Now flip the scope label and re-verify — must NOT match.
    rows[-1]["hash_scope"] = f"investigation:{uuid.uuid4()}"
    result = verify_chain([rows[-1]])
    assert result.valid is False
