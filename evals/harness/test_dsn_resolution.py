"""DEFECT-3: eval runner must prefer MIGRATION_DATABASE_URL over DATABASE_URL.

Cluster A flipped ``DATABASE_URL`` to the ``app_runtime`` role (RLS-respecting).
The eval harness runs an ad-hoc ``psycopg.connect`` outside any
``tenant_session`` to poll for `completed_at` on incidents across the dev
tenant. Without `app.current_tenant` set, the SELECT silently returns zero
rows; every incident "times out" at the eval timeout and the report shows
100% failures regardless of agent quality.

Same shape as DEFECT-2 (cli_resume bootstrap DSN).
"""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

# Allow `python -m pytest` from the repo root by putting the repo on
# sys.path; the absolute import below then resolves under both that form
# and `pytest` invoked from `evals/`.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.run_eval import DEFAULT_DSN, _resolve_dsn  # noqa: E402


def test_prefers_migration_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "MIGRATION_DATABASE_URL",
        "postgresql+psycopg://postgres:pw@host/db",
    )
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://app_runtime:pw@host/db",
    )
    dsn = _resolve_dsn()
    assert "postgres:" in dsn
    assert "app_runtime" not in dsn
    # Normalised — psycopg.connect rejects the +psycopg suffix.
    assert "+psycopg" not in dsn


def test_falls_back_to_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://app_runtime:pw@host/db",
    )
    dsn = _resolve_dsn()
    assert "app_runtime" in dsn
    assert "+psycopg" not in dsn


def test_empty_migration_falls_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """Falsy "" must coerce to fallback (same defensive shape as cli_resume)."""
    monkeypatch.setenv("MIGRATION_DATABASE_URL", "")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://app_runtime:pw@host/db",
    )
    dsn = _resolve_dsn()
    assert "app_runtime" in dsn


def test_default_when_neither_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    dsn = _resolve_dsn()
    # Default DSN is already in normalised form.
    assert dsn == DEFAULT_DSN.replace("postgresql+psycopg://", "postgresql://", 1)
