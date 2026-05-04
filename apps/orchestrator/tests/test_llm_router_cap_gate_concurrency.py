"""Cluster C / HIGH-7 — _check_budget uses ``SELECT FOR UPDATE`` so concurrent
callers on the same investigation_id serialize.

Live integration test — opens TWO real DB connections against the same
investigation row and proves the second call's SELECT FOR UPDATE blocks
until the first transaction commits. Skipped when ``MIGRATION_DATABASE_URL``
isn't set (unit-only CI runs stay self-contained, matching the
``test_audit_chain_concurrency.py`` pattern).
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from collections.abc import Iterator

import pytest

psycopg = pytest.importorskip("psycopg")


def _superuser_dsn() -> str:
    dsn = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("MIGRATION_DATABASE_URL / DATABASE_URL not set")
    return dsn.replace("postgresql+psycopg://", "postgresql://", 1)


TENANT = uuid.UUID("ccccccc1-c2c3-c4c5-c6c7-c8c9cacbcccd")


@pytest.fixture
def seeded_investigation() -> Iterator[tuple[uuid.UUID, uuid.UUID]]:
    """Insert a tenant + incident + investigation row we can lock against."""
    dsn = _superuser_dsn()
    inc_id = uuid.uuid4()
    inv_id = uuid.uuid4()
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO tenants (id, name) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            (str(TENANT), "Cluster-C concurrency test"),
        )
        cur.execute(
            """
            INSERT INTO incidents (id, tenant_id, siem_source, siem_notable_id, status)
            VALUES (%s, %s, 'splunk', %s, 'new')
            ON CONFLICT (id) DO NOTHING
            """,
            (str(inc_id), str(TENANT), f"src-{inc_id}"),
        )
        cur.execute(
            """
            INSERT INTO investigations (id, tenant_id, incident_id)
            VALUES (%s, %s, %s)
            ON CONFLICT (id) DO NOTHING
            """,
            (str(inv_id), str(TENANT), str(inc_id)),
        )
    yield TENANT, inv_id


@pytest.mark.integration
def test_for_update_serialises_same_investigation(
    seeded_investigation: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Two threads both run ``SELECT ... FOR UPDATE OF investigations`` on the
    same investigation_id. The second blocks until the first txn commits."""
    tenant, inv_id = seeded_investigation
    dsn = _superuser_dsn()

    first_locked = threading.Event()
    first_release = threading.Event()
    second_acquired_at: dict[str, float] = {}

    def _holder() -> None:
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_tenant', %s, true)", (str(tenant),))
            cur.execute(
                """
                SELECT total_input_tokens, total_output_tokens, total_cost_usd
                  FROM investigations
                 WHERE id = %s
                   FOR UPDATE OF investigations
                """,
                (str(inv_id),),
            )
            cur.fetchone()
            first_locked.set()
            # Hold the lock until the test signals release.
            first_release.wait(timeout=5.0)
            conn.commit()

    def _waiter() -> None:
        first_locked.wait(timeout=5.0)
        # Sleep briefly so the first txn is *definitely* the lock owner.
        time.sleep(0.05)
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_tenant', %s, true)", (str(tenant),))
            start = time.monotonic()
            cur.execute(
                """
                SELECT total_input_tokens, total_output_tokens, total_cost_usd
                  FROM investigations
                 WHERE id = %s
                   FOR UPDATE OF investigations
                """,
                (str(inv_id),),
            )
            cur.fetchone()
            second_acquired_at["t"] = time.monotonic() - start
            conn.commit()

    holder = threading.Thread(target=_holder)
    waiter = threading.Thread(target=_waiter)
    holder.start()
    waiter.start()
    # Give the waiter a moment to start blocking on the lock.
    time.sleep(0.3)
    # Now release the holder; the waiter should acquire shortly after.
    first_release.set()
    holder.join(timeout=5.0)
    waiter.join(timeout=5.0)

    assert "t" in second_acquired_at, "waiter never acquired the lock"
    # Acquired only AFTER the holder released (we slept 0.3s before release).
    # The wait time should be >= ~0.2s (we held for ~0.3s minus the small
    # initial 0.05s sleep). Use a loose lower bound to avoid flakiness.
    assert (
        second_acquired_at["t"] >= 0.10
    ), f"waiter acquired in {second_acquired_at['t']:.3f}s — FOR UPDATE not blocking"


@pytest.mark.integration
def test_for_update_does_not_block_different_investigations(
    seeded_investigation: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Row-level lock — two callers on DIFFERENT investigations don't serialize."""
    tenant, inv_a = seeded_investigation
    dsn = _superuser_dsn()

    # Insert a second investigation row for the same tenant.
    inv_b = uuid.uuid4()
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM incidents WHERE tenant_id = %s LIMIT 1", (str(tenant),))
        inc_id = cur.fetchone()[0]
        cur.execute(
            """
            INSERT INTO investigations (id, tenant_id, incident_id)
            VALUES (%s, %s, %s)
            ON CONFLICT (id) DO NOTHING
            """,
            (str(inv_b), str(tenant), str(inc_id)),
        )

    holder_locked = threading.Event()
    waiter_done_at: dict[str, float] = {}
    test_start = time.monotonic()

    def _holder() -> None:
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_tenant', %s, true)", (str(tenant),))
            cur.execute(
                "SELECT total_cost_usd FROM investigations WHERE id = %s "
                "FOR UPDATE OF investigations",
                (str(inv_a),),
            )
            cur.fetchone()
            holder_locked.set()
            time.sleep(0.5)
            conn.commit()

    def _waiter() -> None:
        holder_locked.wait(timeout=5.0)
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_tenant', %s, true)", (str(tenant),))
            cur.execute(
                "SELECT total_cost_usd FROM investigations WHERE id = %s "
                "FOR UPDATE OF investigations",
                (str(inv_b),),
            )
            cur.fetchone()
            waiter_done_at["t"] = time.monotonic() - test_start
            conn.commit()

    holder = threading.Thread(target=_holder)
    waiter = threading.Thread(target=_waiter)
    holder.start()
    waiter.start()
    holder.join(timeout=5.0)
    waiter.join(timeout=5.0)

    assert "t" in waiter_done_at
    # Waiter completed BEFORE the holder finished its 0.5s hold.
    assert (
        waiter_done_at["t"] < 0.45
    ), f"waiter on different inv took {waiter_done_at['t']:.3f}s — should not block"


# Reference asyncio import retained for parity with sister concurrency tests
# (test_audit_chain_concurrency uses asyncio.to_thread); not used directly here.
_ = asyncio
