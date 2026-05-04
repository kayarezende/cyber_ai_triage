"""Cluster C / HIGH-8 — cost columns widened to NUMERIC(14,6).

Pre-cluster-C, ``investigations.total_cost_usd`` was NUMERIC(10,6) — capped
at $9999.999999. A long Opus-driven investigation could plausibly exceed
that. After widening, $1000+ values insert without overflow. Live test:
runs against the actual DB so the column type is exercised, not just
asserted in code.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from decimal import Decimal

import pytest
from sqlalchemy import create_engine, text

from sentient_orchestrator.llm.usage import update_investigation_totals


def _superuser_dsn() -> str:
    dsn = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("MIGRATION_DATABASE_URL / DATABASE_URL not set")
    if "+psycopg" not in dsn and dsn.startswith("postgresql://"):
        dsn = dsn.replace("postgresql://", "postgresql+psycopg://", 1)
    return dsn


TENANT = uuid.UUID("ddddddd1-d2d3-d4d5-d6d7-d8d9dadbdcdd")


@pytest.fixture
def seeded_investigation() -> Iterator[tuple[uuid.UUID, uuid.UUID]]:
    engine = create_engine(_superuser_dsn())
    inc_id = uuid.uuid4()
    inv_id = uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (id, name) VALUES (:id, :name) " "ON CONFLICT (id) DO NOTHING"
            ),
            {"id": str(TENANT), "name": "Cluster-C decimal overflow test"},
        )
        conn.execute(
            text("""
                INSERT INTO incidents (id, tenant_id, siem_source, siem_notable_id, status)
                VALUES (:id, :tid, 'splunk', :seid, 'new')
                ON CONFLICT (id) DO NOTHING
                """),
            {"id": str(inc_id), "tid": str(TENANT), "seid": f"src-{inc_id}"},
        )
        conn.execute(
            text("""
                INSERT INTO investigations (id, tenant_id, incident_id)
                VALUES (:id, :tid, :inc)
                ON CONFLICT (id) DO NOTHING
                """),
            {"id": str(inv_id), "tid": str(TENANT), "inc": str(inc_id)},
        )
    yield TENANT, inv_id


@pytest.mark.integration
def test_thousand_dollar_cost_does_not_overflow(
    seeded_investigation: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Accumulate $1000.50 onto the investigation row — must not overflow.

    Pre-cluster-C this would raise ``numeric field overflow`` (NUMERIC(10,6)
    max = 9999.999999). Post-widen to NUMERIC(14,6), $1000.50 fits with
    headroom up to $99,999,999.999999.
    """
    _tenant, inv_id = seeded_investigation
    engine = create_engine(_superuser_dsn())
    with engine.begin() as conn:
        update_investigation_totals(
            conn,
            investigation_id=inv_id,
            input_tokens=1_000_000,
            output_tokens=500_000,
            cost_usd=Decimal("1000.500000"),
        )
        row = conn.execute(
            text("SELECT total_cost_usd FROM investigations WHERE id = :id"),
            {"id": str(inv_id)},
        ).first()
    assert row is not None
    assert row[0] == Decimal("1000.500000")


@pytest.mark.integration
def test_decimal_precision_round_trips(
    seeded_investigation: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Sanity: a 6-decimal value writes + reads back with no float drift.
    Catches the pre-cluster-C float-binding hazard where 0.1 + 0.2 + 0.3
    would write to NUMERIC and round-trip as 0.600000... or 0.5999999..."""
    _tenant, inv_id = seeded_investigation
    engine = create_engine(_superuser_dsn())
    with engine.begin() as conn:
        for amount in ("0.100000", "0.200000", "0.300000"):
            update_investigation_totals(
                conn,
                investigation_id=inv_id,
                input_tokens=0,
                output_tokens=0,
                cost_usd=Decimal(amount),
            )
        row = conn.execute(
            text("SELECT total_cost_usd FROM investigations WHERE id = :id"),
            {"id": str(inv_id)},
        ).first()
    assert row is not None
    assert row[0] == Decimal("0.600000")  # exact, no float drift
