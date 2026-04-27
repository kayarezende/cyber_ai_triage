"""Wk-10 admin router tests (5 surfaces + auth gate).

DB + audit + crypto + httpx are patched at each router module so the suite
runs without Postgres / MinIO / a real Splunk box. Auth gate is exercised
via the wk-10 `X-Dev-Role` middleware header — `analyst` returns 403 from
the `RequireAdmin` dep, `admin` is the default.

One file covers all five routers because the IO contract is uniform: each
endpoint runs a single `tenant_session` block + (optionally) emits an
audit row. Per-router files would mostly duplicate the patch fixture.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

ADMIN_HEADERS = {"X-Dev-Role": "admin"}
ANALYST_HEADERS = {"X-Dev-Role": "analyst"}


# ---- shared DB + audit patch helpers


@pytest.fixture
def patch_admin_db(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch tenant_session + insert_audit_log inside every admin router.

    Tests load `responses` with the rows each `conn.execute(...)` should
    return; results pop from the front. Audit calls land in `audits`.
    """
    state: dict[str, Any] = {"responses": [], "calls": [], "audits": []}

    @contextmanager
    def fake_session(_tenant_id: Any) -> Iterator[MagicMock]:
        conn = MagicMock(name="conn")

        def capture_execute(stmt: Any, params: dict[str, Any] | None = None) -> Any:
            state["calls"].append((str(stmt), params or {}))
            if not state["responses"]:
                return MagicMock(
                    first=lambda: None,
                    all=lambda: [],
                    rowcount=0,
                )
            response = state["responses"].pop(0)
            if isinstance(response, list):
                return MagicMock(
                    first=lambda r=response: r[0] if r else None,
                    all=lambda r=response: r,
                    rowcount=len(response),
                )
            return MagicMock(
                first=lambda r=response: r,
                all=lambda r=response: [r] if r else [],
                rowcount=1 if response else 0,
            )

        conn.execute.side_effect = capture_execute
        yield conn

    def fake_audit(
        _conn: Any,
        *,
        tenant_id: Any,
        investigation_id: Any,
        actor: str,
        action: str,
        details: dict[str, Any],
    ) -> None:
        state["audits"].append(
            {
                "tenant_id": str(tenant_id),
                "investigation_id": str(investigation_id) if investigation_id else None,
                "actor": actor,
                "action": action,
                "details": details,
            }
        )

    for module in (
        "sentient_api.routers.admin.llm_roles",
        "sentient_api.routers.admin.hitl_policies",
        "sentient_api.routers.admin.budgets",
        "sentient_api.routers.admin.splunk_creds",
        "sentient_api.routers.admin.users",
    ):
        monkeypatch.setattr(f"{module}.tenant_session", fake_session)
        if module != "sentient_api.routers.admin.llm_roles":
            # llm_roles imports insert_audit_log too; path identical.
            monkeypatch.setattr(f"{module}.insert_audit_log", fake_audit)
    monkeypatch.setattr(
        "sentient_api.routers.admin.llm_roles.insert_audit_log", fake_audit
    )
    return state


# =====================================================================
# auth gate
# =====================================================================


def test_admin_endpoint_403_for_analyst(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    r = wk9_client.get("/api/admin/llm-roles", headers=ANALYST_HEADERS)
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "admin_required"


def test_admin_endpoint_400_on_invalid_role_header(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    r = wk9_client.get(
        "/api/admin/llm-roles", headers={"X-Dev-Role": "wizard"}
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_role_header"


# =====================================================================
# llm_roles
# =====================================================================


def test_list_llm_roles(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [
        [
            ("triage", "google/gemini-3-flash-preview", ["x-fallback"], 4096, 0.2, 30, True),
            ("investigation", "anthropic/claude-opus-4-7", [], 8192, 0.3, 60, True),
        ]
    ]
    r = wk9_client.get("/api/admin/llm-roles", headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["items"]) == 2
    assert body["items"][0]["role"] == "triage"
    assert body["items"][0]["primary_model"] == "google/gemini-3-flash-preview"
    assert body["items"][0]["fallback_chain"] == ["x-fallback"]
    assert body["items"][0]["enabled"] is True


def test_update_llm_role_happy_path(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [
        ("triage", "anthropic/claude-haiku-4-5", ["fallback-1"], 2048, 0.1, 20, True),
    ]
    body = {
        "primary_model": "anthropic/claude-haiku-4-5",
        "fallback_chain": ["fallback-1"],
        "max_tokens": 2048,
        "temperature": 0.1,
        "timeout_seconds": 20,
        "enabled": True,
    }
    r = wk9_client.put(
        "/api/admin/llm-roles/triage", json=body, headers=ADMIN_HEADERS
    )
    assert r.status_code == 200, r.text
    assert r.json()["primary_model"] == "anthropic/claude-haiku-4-5"
    audits = patch_admin_db["audits"]
    assert len(audits) == 1
    assert audits[0]["action"] == "admin_llm_role_updated"
    assert audits[0]["details"]["role"] == "triage"


def test_update_llm_role_404_when_missing(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [None]
    body = {
        "primary_model": "x",
        "fallback_chain": [],
        "max_tokens": 1024,
        "temperature": 0.0,
        "timeout_seconds": 10,
        "enabled": True,
    }
    r = wk9_client.put(
        "/api/admin/llm-roles/triage", json=body, headers=ADMIN_HEADERS
    )
    assert r.status_code == 404
    assert r.json()["detail"] == "llm_role_not_found"


def test_update_llm_role_rejects_unknown_role_via_path(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    body = {
        "primary_model": "x",
        "fallback_chain": [],
        "max_tokens": 1024,
        "temperature": 0.0,
        "timeout_seconds": 10,
        "enabled": True,
    }
    r = wk9_client.put(
        "/api/admin/llm-roles/wizard", json=body, headers=ADMIN_HEADERS
    )
    assert r.status_code == 422  # path Literal validation kicks in


# =====================================================================
# hitl_policies
# =====================================================================


def test_list_hitl_policies(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    pid = uuid4()
    patch_admin_db["responses"] = [
        [
            (str(pid), None, "default_require_approval", {"op": "always_true"}, 100, True),
        ]
    ]
    r = wk9_client.get("/api/admin/hitl-policies", headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["name"] == "default_require_approval"
    assert items[0]["tenant_id"] is None  # global rule


def test_create_hitl_policy_valid(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    pid = uuid4()
    patch_admin_db["responses"] = [
        (str(pid), str(uuid4()), "auto-approve-low", {"op": "always_false"}, 50, True),
    ]
    r = wk9_client.post(
        "/api/admin/hitl-policies",
        json={
            "name": "auto-approve-low",
            "rule_expression": {"op": "always_false"},
            "priority": 50,
            "enabled": True,
        },
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 201, r.text
    assert r.json()["name"] == "auto-approve-low"
    audits = patch_admin_db["audits"]
    assert audits and audits[0]["action"] == "admin_hitl_policy_created"


def test_create_hitl_policy_400_on_invalid_expression(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    """Bogus op should be rejected at validate time, never INSERTed."""
    r = wk9_client.post(
        "/api/admin/hitl-policies",
        json={
            "name": "bad",
            "rule_expression": {"op": "totally_invalid_op"},
            "priority": 100,
            "enabled": True,
        },
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_rule_expression"
    assert patch_admin_db["calls"] == []  # never reached the DB


def test_update_hitl_policy_404(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [None]
    r = wk9_client.put(
        f"/api/admin/hitl-policies/{uuid4()}",
        json={
            "name": "x",
            "rule_expression": {"op": "always_true"},
            "priority": 100,
            "enabled": True,
        },
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 404


def test_delete_hitl_policy_404_when_missing(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [None]
    r = wk9_client.delete(
        f"/api/admin/hitl-policies/{uuid4()}", headers=ADMIN_HEADERS
    )
    assert r.status_code == 404


def test_delete_hitl_policy_204_on_success(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [{"deleted": True}]  # truthy → rowcount=1
    r = wk9_client.delete(
        f"/api/admin/hitl-policies/{uuid4()}", headers=ADMIN_HEADERS
    )
    assert r.status_code == 204
    audits = patch_admin_db["audits"]
    assert audits and audits[0]["action"] == "admin_hitl_policy_deleted"


# =====================================================================
# budgets
# =====================================================================


def test_get_budgets(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [(5, 200.00, 0.50, 100_000)]
    r = wk9_client.get("/api/admin/budgets", headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["max_concurrent_investigations"] == 5
    assert body["monthly_llm_budget_usd"] == 200.00
    assert body["per_investigation_budget_usd"] == 0.5
    assert body["per_investigation_token_cap"] == 100_000


def test_update_budgets_happy_path(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [(10, 500.00, 1.00, 200_000)]
    r = wk9_client.put(
        "/api/admin/budgets",
        json={
            "max_concurrent_investigations": 10,
            "monthly_llm_budget_usd": 500.0,
            "per_investigation_budget_usd": 1.0,
            "per_investigation_token_cap": 200_000,
        },
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 200, r.text
    audits = patch_admin_db["audits"]
    assert audits and audits[0]["action"] == "admin_budgets_updated"


def test_update_budgets_accepts_nulls() -> None:
    """Null on every field should disable the cap; verified via Pydantic
    parse, no DB hit needed."""
    from sentient_api.routers.admin.budgets import TenantBudgetsUpdate
    body = TenantBudgetsUpdate.model_validate({})  # every field optional
    assert body.max_concurrent_investigations is None
    assert body.monthly_llm_budget_usd is None
    assert body.per_investigation_budget_usd is None
    assert body.per_investigation_token_cap is None


def test_update_budgets_rejects_negative_values(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    r = wk9_client.put(
        "/api/admin/budgets",
        json={"per_investigation_budget_usd": -1.0},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 422  # ge=0.0 violation


# =====================================================================
# splunk_creds
# =====================================================================


@pytest.fixture
def patch_splunk_probe(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"calls": [], "raise": None, "status_code": 200}

    def fake_get(url: str, **kw: Any) -> MagicMock:
        state["calls"].append({"url": url, "kw": kw})
        if state["raise"] is not None:
            raise state["raise"]
        resp = MagicMock()
        resp.status_code = state["status_code"]
        return resp

    monkeypatch.setattr(
        "sentient_api.routers.admin.splunk_creds.httpx.get", fake_get
    )
    monkeypatch.setattr(
        "sentient_api.routers.admin.splunk_creds.encrypt", lambda s: b"E:" + s.encode()
    )
    return state


def test_get_splunk_config(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [("splunk.local", "dual", True, True)]
    r = wk9_client.get("/api/admin/splunk", headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["splunk_host"] == "splunk.local"
    assert body["writeback_mode"] == "dual"
    assert body["has_management_token"] is True
    assert body["has_hec_token"] is True


def test_get_splunk_config_404_when_tenant_missing(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [None]
    r = wk9_client.get("/api/admin/splunk", headers=ADMIN_HEADERS)
    assert r.status_code == 404


def test_update_splunk_with_probe(
    wk9_client: TestClient,
    patch_admin_db: dict[str, Any],
    patch_splunk_probe: dict[str, Any],
) -> None:
    patch_splunk_probe["status_code"] = 200
    patch_admin_db["responses"] = [("splunk.local", "hec_only", True, True)]
    r = wk9_client.put(
        "/api/admin/splunk",
        json={
            "splunk_host": "splunk.local",
            "writeback_mode": "hec_only",
            "splunk_token": "tok-mgmt",
            "splunk_hec_token": "tok-hec",
        },
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 200, r.text
    assert r.json()["splunk_host"] == "splunk.local"
    assert "splunk.local:8089/services/server/info" in patch_splunk_probe["calls"][0]["url"]
    audits = patch_admin_db["audits"]
    assert audits and audits[0]["action"] == "admin_splunk_config_updated"
    assert audits[0]["details"]["token_rotated"] is True
    assert audits[0]["details"]["hec_rotated"] is True


def test_update_splunk_probe_401_returns_400(
    wk9_client: TestClient,
    patch_admin_db: dict[str, Any],
    patch_splunk_probe: dict[str, Any],
) -> None:
    patch_splunk_probe["status_code"] = 401
    r = wk9_client.put(
        "/api/admin/splunk",
        json={
            "splunk_host": "splunk.local",
            "splunk_token": "bad",
        },
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "probe_unauthorized"
    assert patch_admin_db["calls"] == []  # never wrote


def test_update_splunk_probe_required_when_token_supplied_implicitly(
    wk9_client: TestClient,
    patch_admin_db: dict[str, Any],
    patch_splunk_probe: dict[str, Any],
) -> None:
    """Skipping the probe without supplying a token requires explicit opt-in."""
    r = wk9_client.put(
        "/api/admin/splunk",
        json={"splunk_host": "splunk.local"},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "probe_requires_token"


def test_update_splunk_skip_probe_without_token(
    wk9_client: TestClient,
    patch_admin_db: dict[str, Any],
    patch_splunk_probe: dict[str, Any],
) -> None:
    """`skip_probe=true` lets the admin update host/writeback_mode without
    re-supplying secrets. COALESCE in the UPDATE preserves existing token."""
    patch_admin_db["responses"] = [("splunk-new.local", "dual", True, True)]
    r = wk9_client.put(
        "/api/admin/splunk",
        json={
            "splunk_host": "splunk-new.local",
            "writeback_mode": "dual",
            "skip_probe": True,
        },
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 200
    assert patch_splunk_probe["calls"] == []  # probe skipped


# =====================================================================
# users
# =====================================================================


def test_list_users(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    uid = uuid4()
    patch_admin_db["responses"] = [
        [
            (str(uid), "admin@founder.local", "admin", "oid-1", datetime.now(UTC)),
        ]
    ]
    r = wk9_client.get("/api/admin/users", headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["email"] == "admin@founder.local"
    assert items[0]["role"] == "admin"


def test_invite_user_201(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    uid = uuid4()
    patch_admin_db["responses"] = [
        (str(uid), "new@founder.local", "analyst", None, None),
    ]
    r = wk9_client.post(
        "/api/admin/users",
        json={"email": "New@Founder.local", "role": "analyst"},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "new@founder.local"
    audits = patch_admin_db["audits"]
    assert audits and audits[0]["action"] == "admin_user_invited"
    # Email lowercased before INSERT.
    assert audits[0]["details"]["email"] == "new@founder.local"


def test_invite_user_rejects_bad_email(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    r = wk9_client.post(
        "/api/admin/users",
        json={"email": "not-an-email", "role": "analyst"},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 422


def test_update_user_role_404(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    patch_admin_db["responses"] = [None]
    r = wk9_client.patch(
        f"/api/admin/users/{uuid4()}",
        json={"role": "admin"},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 404


def test_update_user_role_happy_path(
    wk9_client: TestClient, patch_admin_db: dict[str, Any]
) -> None:
    uid = uuid4()
    patch_admin_db["responses"] = [
        (str(uid), "user@founder.local", "admin", None, None),
    ]
    r = wk9_client.patch(
        f"/api/admin/users/{uid}",
        json={"role": "admin"},
        headers=ADMIN_HEADERS,
    )
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"
    audits = patch_admin_db["audits"]
    assert audits and audits[0]["action"] == "admin_user_role_changed"
