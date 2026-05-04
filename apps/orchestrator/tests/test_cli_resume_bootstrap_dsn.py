"""DEFECT-2 fix: cli_resume._load_tenant_id uses MIGRATION_DATABASE_URL first.

Cluster A flipped ``DATABASE_URL`` from postgres superuser to ``app_runtime``,
which respects RLS. The CLI's pre-tenant_session bootstrap SELECT against the
investigations row needs a role that bypasses RLS to read across tenants;
``MIGRATION_DATABASE_URL`` is the cluster-A canonical path. Pre-fix the CLI
read returned 0 rows for valid UUIDs and printed "investigation not found".
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest

from sentient_orchestrator import cli_resume as cli_mod

INV = UUID("33333333-3333-3333-3333-333333333333")
TENANT = UUID("11111111-1111-1111-1111-111111111111")


class _FakeCursor:
    def __init__(self, row: tuple[str, ...] | None) -> None:
        self._row = row
        self.executed: tuple[str, tuple[str, ...]] | None = None

    def execute(self, sql: str, params: tuple[str, ...]) -> None:
        self.executed = (sql, params)

    def fetchone(self) -> tuple[str, ...] | None:
        return self._row

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *_a: Any) -> None:
        pass


class _FakeConn:
    def __init__(self, dsn: str, row: tuple[str, ...] | None) -> None:
        self.dsn = dsn
        self._row = row

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._row)

    def __enter__(self) -> _FakeConn:
        return self

    def __exit__(self, *_a: Any) -> None:
        pass


def test_prefers_migration_database_url_over_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When both are set, MIGRATION_DATABASE_URL wins (cluster-A bypass path)."""
    monkeypatch.setenv(
        "MIGRATION_DATABASE_URL",
        "postgresql+psycopg://postgres:pw@host/db",
    )
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://app_runtime:pw@host/db",
    )
    used: dict[str, str] = {}

    def fake_connect(dsn: str) -> _FakeConn:
        used["dsn"] = dsn
        return _FakeConn(dsn, (str(TENANT),))

    monkeypatch.setattr(cli_mod.psycopg, "connect", fake_connect)
    result = cli_mod._load_tenant_id(INV)
    assert result == TENANT
    assert "postgres:" in used["dsn"]
    assert "app_runtime" not in used["dsn"]


def test_falls_back_to_database_url_when_migration_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy support — minimal CI without cluster-A schema still functional."""
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://app_runtime:pw@host/db",
    )
    used: dict[str, str] = {}

    def fake_connect(dsn: str) -> _FakeConn:
        used["dsn"] = dsn
        return _FakeConn(dsn, (str(TENANT),))

    monkeypatch.setattr(cli_mod.psycopg, "connect", fake_connect)
    result = cli_mod._load_tenant_id(INV)
    assert result == TENANT
    assert "app_runtime" in used["dsn"]


def test_raises_when_neither_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="must be set"):
        cli_mod._load_tenant_id(INV)


def test_empty_migration_falls_through_to_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`os.environ.get(...) or os.environ.get(...)` falsy-coerces "" — pin it.

    A future reader might "tighten" the check to `is not None`, which would
    silently regress this case (export MIGRATION_DATABASE_URL="" then expect
    DATABASE_URL to win).
    """
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://app_runtime:pw@host/db",
    )
    used: dict[str, str] = {}

    def fake_connect(dsn: str) -> _FakeConn:
        used["dsn"] = dsn
        return _FakeConn(dsn, (str(TENANT),))

    monkeypatch.setattr(cli_mod.psycopg, "connect", fake_connect)
    cli_mod._load_tenant_id(INV)
    assert "app_runtime" in used["dsn"]


def test_raises_when_investigation_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "MIGRATION_DATABASE_URL",
        "postgresql+psycopg://postgres:pw@host/db",
    )
    monkeypatch.setattr(cli_mod.psycopg, "connect", lambda dsn: _FakeConn(dsn, None))
    with pytest.raises(RuntimeError, match="not found"):
        cli_mod._load_tenant_id(INV)


def test_strips_psycopg_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    """psycopg.connect rejects 'postgresql+psycopg://' URI; helper must strip."""
    monkeypatch.setenv(
        "MIGRATION_DATABASE_URL",
        "postgresql+psycopg://postgres:pw@host/db",
    )
    used: dict[str, str] = {}

    def fake_connect(dsn: str) -> _FakeConn:
        used["dsn"] = dsn
        return _FakeConn(dsn, (str(TENANT),))

    monkeypatch.setattr(cli_mod.psycopg, "connect", fake_connect)
    cli_mod._load_tenant_id(INV)
    assert used["dsn"].startswith("postgresql://")
    assert "+psycopg" not in used["dsn"]
