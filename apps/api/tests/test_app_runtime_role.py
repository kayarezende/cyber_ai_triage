"""Cluster A (CRIT-1 + CRIT-2): live-DB tests for the app_runtime role.

These connect against the compose Postgres as `app_runtime` (the
non-superuser role provisioned by migration `e5f7a1b9c4d6`) and verify that
the load-bearing security controls actually fire:

* RLS scopes SELECT to `app.current_tenant` (cross-tenant rows invisible).
* `audit_log` UPDATE/DELETE/TRUNCATE all fail (mix of privilege denial +
  trigger rejection — both layers exist deliberately).
* `audit_log` INSERT works (via `audit_writer` membership + direct grants).

Skipped when `MIGRATION_DATABASE_URL` and `APP_RUNTIME_PASSWORD` aren't set
in the test env, so unit-only CI runs stay self-contained. Founder runs the
full suite locally against `docker compose up -d postgres`.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

psycopg = pytest.importorskip("psycopg")


def _superuser_dsn() -> str:
    dsn = os.environ.get("MIGRATION_DATABASE_URL")
    if not dsn:
        pytest.skip("MIGRATION_DATABASE_URL not set")
    return dsn.replace("postgresql+psycopg://", "postgresql://", 1)


def _app_runtime_dsn() -> str:
    password = os.environ.get("APP_RUNTIME_PASSWORD")
    if not password:
        pytest.skip("APP_RUNTIME_PASSWORD not set")
    db = os.environ.get("POSTGRES_DB", "sentient")
    # Reuse host/port from MIGRATION_DATABASE_URL by parsing minimally.
    superuser = _superuser_dsn()
    # postgresql://user:pw@host:port/db → swap user:pw and db.
    rest = superuser.split("@", 1)[1]  # host:port/db
    host_port = rest.split("/", 1)[0]
    return f"postgresql://app_runtime:{password}@{host_port}/{db}"


TENANT_A = uuid.UUID("aaaa0000-0000-0000-0000-000000000001")
TENANT_B = uuid.UUID("bbbb0000-0000-0000-0000-000000000002")


@pytest.fixture
def seeded_tenants() -> Iterator[tuple[uuid.UUID, uuid.UUID, int]]:
    """Insert two tenants + one incident in tenant A as superuser; yield IDs.

    Cleans up everything on teardown — the test DB is shared with the dev
    stack so we must not leave orphan rows.
    """
    superuser = _superuser_dsn()
    incident_id = uuid.uuid4()
    with psycopg.connect(superuser, autocommit=True) as conn, conn.cursor() as cur:
        for tid in (TENANT_A, TENANT_B):
            cur.execute(
                "INSERT INTO tenants (id, name) VALUES (%s, %s) " "ON CONFLICT (id) DO NOTHING",
                (str(tid), f"Cluster-A test tenant {tid.hex[:6]}"),
            )
        cur.execute(
            "INSERT INTO incidents (id, tenant_id, status) VALUES (%s, %s, 'new')",
            (str(incident_id), str(TENANT_A)),
        )
    try:
        yield TENANT_A, TENANT_B, incident_id
    finally:
        with psycopg.connect(superuser, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM incidents WHERE id = %s", (str(incident_id),))
            for tid in (TENANT_A, TENANT_B):
                cur.execute("DELETE FROM tenants WHERE id = %s", (str(tid),))


@pytest.fixture
def app_runtime_conn() -> Iterator[psycopg.Connection]:
    dsn = _app_runtime_dsn()
    try:
        conn = psycopg.connect(dsn, connect_timeout=2)
    except Exception as exc:  # noqa: BLE001 — surface as a skip
        pytest.skip(f"app_runtime cannot connect: {exc}")
    try:
        yield conn
    finally:
        conn.close()


@pytest.mark.integration
def test_cross_tenant_select_returns_zero_rows(
    seeded_tenants: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    app_runtime_conn: psycopg.Connection,
) -> None:
    """RLS in action: app_runtime sees only its own tenant's incidents."""
    tenant_a, tenant_b, incident_id = seeded_tenants
    with app_runtime_conn.cursor() as cur:
        # Bind to tenant B; the row was inserted under tenant A.
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)",
            (str(tenant_b),),
        )
        cur.execute("SELECT id FROM incidents WHERE id = %s", (str(incident_id),))
        assert cur.fetchall() == []

        # Same connection, switch to tenant A → row visible.
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)",
            (str(tenant_a),),
        )
        cur.execute("SELECT id FROM incidents WHERE id = %s", (str(incident_id),))
        rows = cur.fetchall()
        assert len(rows) == 1
        assert str(rows[0][0]) == str(incident_id)


@pytest.mark.integration
def test_audit_log_truncate_denied(
    seeded_tenants: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    app_runtime_conn: psycopg.Connection,
) -> None:
    """CRIT-2: TRUNCATE must fail (privilege denial OR new BEFORE trigger)."""
    tenant_a, _, _ = seeded_tenants
    with app_runtime_conn.cursor() as cur:
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)",
            (str(tenant_a),),
        )
        with pytest.raises(psycopg.errors.Error):
            cur.execute("TRUNCATE audit_log")
    app_runtime_conn.rollback()


@pytest.mark.integration
def test_audit_log_update_denied(
    seeded_tenants: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    app_runtime_conn: psycopg.Connection,
) -> None:
    """CRIT-1: UPDATE on audit_log must fail at privilege check (the role
    only has INSERT + SELECT)."""
    tenant_a, _, _ = seeded_tenants
    with app_runtime_conn.cursor() as cur:
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)",
            (str(tenant_a),),
        )
        with pytest.raises(psycopg.errors.Error):
            cur.execute("UPDATE audit_log SET action = 'tampered' WHERE id = 1")
    app_runtime_conn.rollback()


@pytest.mark.integration
def test_audit_log_delete_denied(
    seeded_tenants: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    app_runtime_conn: psycopg.Connection,
) -> None:
    """CRIT-1: DELETE on audit_log must fail at privilege check."""
    tenant_a, _, _ = seeded_tenants
    with app_runtime_conn.cursor() as cur:
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)",
            (str(tenant_a),),
        )
        with pytest.raises(psycopg.errors.Error):
            cur.execute("DELETE FROM audit_log WHERE id = 1")
    app_runtime_conn.rollback()


@pytest.mark.integration
def test_audit_log_insert_succeeds(
    seeded_tenants: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    app_runtime_conn: psycopg.Connection,
) -> None:
    """app_runtime must still be able to write audit rows (via direct
    INSERT grant + audit_writer membership). Roll back so the row never
    persists — append-only triggers reject any explicit cleanup."""
    tenant_a, _, _ = seeded_tenants
    with app_runtime_conn.cursor() as cur:
        cur.execute(
            "SELECT set_config('app.current_tenant', %s, true)",
            (str(tenant_a),),
        )
        cur.execute(
            """
            INSERT INTO audit_log
                (tenant_id, investigation_id, actor, action, details, hash_scope)
            VALUES
                (%s, NULL, 'pytest:role', 'role_smoke',
                 '{"k": "v"}'::jsonb, %s)
            RETURNING id, content_hash
            """,
            (str(tenant_a), f"tenant:{tenant_a}"),
        )
        row = cur.fetchone()
        assert row is not None
        _id, content_hash = row
        assert content_hash and len(content_hash) == 64
    app_runtime_conn.rollback()
