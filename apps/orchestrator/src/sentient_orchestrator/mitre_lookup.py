"""MITRE ATT&CK technique description lookup.

Reads the local `mitre_techniques` cache (seeded wk-1 from STIX 2.1) so the
triage prompt can inject technique names + descriptions alongside the bare
T-codes the SIEM provided.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection


def fetch_technique_descriptions(
    conn: Connection,
    technique_ids: list[str],
) -> dict[str, str]:
    """Return `{T_code: "name — description"}` for any IDs found in the cache.

    Missing IDs are silently omitted; callers handle "(unknown technique)"
    rendering. Single SQL call regardless of list size.
    """
    if not technique_ids:
        return {}

    rows = conn.execute(
        text(
            """
            SELECT technique_id, name, description
            FROM mitre_techniques
            WHERE technique_id = ANY(:ids)
            """
        ),
        {"ids": list(technique_ids)},
    ).all()

    out: dict[str, str] = {}
    for tid, name, desc in rows:
        if not name:
            continue
        if desc:
            out[tid] = f"{name} — {_truncate(desc, 240)}"
        else:
            out[tid] = name
    return out


def _truncate(text_value: str, limit: int) -> str:
    """Trim long descriptions so the prompt context stays bounded."""
    cleaned = " ".join(text_value.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1].rstrip() + "…"


__all__ = ["fetch_technique_descriptions"]
