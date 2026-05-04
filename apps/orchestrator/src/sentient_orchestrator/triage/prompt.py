"""Tier-1 triage prompt builder.

System prompt is fixed across roles + tenants; user message is built per
incident from the OCSF Detection Finding produced by the wk-3 mapper plus
the MITRE technique descriptions resolved from the local cache.
"""

from __future__ import annotations

from sentient_ocsf.detection_finding import DetectionFinding
from sentient_orchestrator.investigation.sanitizer import sanitize_untrusted

SYSTEM_PROMPT = """You are a Tier-1 SOC triage analyst for an Australian MSSP.

Given a security finding from a SIEM, you classify severity, estimate \
confidence, suggest MITRE ATT&CK techniques, and list entities that warrant \
deeper Tier-2 investigation.

Output ONLY structured JSON conforming to the TriageOutput schema. No prose. \
No markdown. No code fences.

Severity scale (must use one of these five values):
- info: routine activity; no analyst action required.
- low: noteworthy but no immediate risk; monitor only.
- medium: warrants Tier-2 investigation; potential incident.
- high: likely incident; urgent investigation required.
- critical: confirmed compromise indicator; immediate response.

Confidence: integer 0-100. >=80 = strong signal. 50-79 = plausible. \
<50 = weak or ambiguous.

MITRE technique guesses: T-codes only (e.g. `T1059.001`, `T1071`). Use the \
SIEM-provided technique annotations as the starting point but reason \
independently about additional likely techniques. Empty list if none apply.

Entities to investigate: bare strings — hostnames, IPs, usernames, file \
hashes — anything Tier-2 should pivot on. Empty list if nothing stood out.

Reasoning: 1-3 sentences explaining the verdict. Focus on what evidence \
drove the severity + confidence call. Captured in the audit trail."""


def build_user_message(
    finding: DetectionFinding,
    mitre_descs: dict[str, str],
) -> str:
    """Build the per-incident user message from the OCSF finding + MITRE cache."""
    info = finding.finding_info
    sev_name = finding.severity_id.name.lower() if finding.severity_id else "unknown"

    lines: list[str] = [
        "Finding:",
        f"- Title: {sanitize_untrusted(info.title)}",
        f"- SIEM-reported severity: {sev_name}",
    ]
    if info.desc:
        lines.append(f"- Description: {sanitize_untrusted(info.desc)}")
    if info.analytic and info.analytic.name:
        lines.append(f"- Analytic: {sanitize_untrusted(info.analytic.name)}")

    actor_name = (
        finding.actor.user.name
        if finding.actor and finding.actor.user and finding.actor.user.name
        else None
    )
    lines.append(f"\nActor: {sanitize_untrusted(actor_name) if actor_name else '(none)'}")
    lines.append(f"Source: {_endpoint_str(finding.src_endpoint)}")
    lines.append(f"Destination: {_endpoint_str(finding.dst_endpoint)}")

    if finding.mitre_techniques or finding.attacks:
        lines.append("\nMITRE annotations from SIEM:")
        seen: set[str] = set()
        for tcode in finding.mitre_techniques:
            if tcode in seen:
                continue
            seen.add(tcode)
            desc = mitre_descs.get(tcode)
            lines.append(f"- {tcode}" + (f": {sanitize_untrusted(desc)}" if desc else ""))
        for attack in finding.attacks:
            tcode = attack.technique.uid
            if tcode in seen:
                continue
            seen.add(tcode)
            desc = mitre_descs.get(tcode)
            lines.append(f"- {tcode}" + (f": {sanitize_untrusted(desc)}" if desc else ""))
    else:
        lines.append("\nMITRE annotations from SIEM: (none)")

    return "\n".join(lines)


def _endpoint_str(endpoint: object) -> str:
    """Render NetworkEndpoint as `hostname (ip[:port])`, or '(none)'.

    Sanitizes hostname + ip strings (Splunk-controlled). Port is int-cast so
    a control-char-laden numeric never reaches the prompt.
    """
    if endpoint is None:
        return "(none)"
    hostname = getattr(endpoint, "hostname", None)
    ip = getattr(endpoint, "ip", None)
    port = getattr(endpoint, "port", None)
    if not hostname and not ip:
        return "(none)"
    parts: list[str] = []
    if hostname:
        parts.append(sanitize_untrusted(str(hostname)))
    addr = sanitize_untrusted(str(ip)) if ip else None
    if addr and port:
        addr = f"{addr}:{int(port)}"
    if addr:
        parts.append(f"({addr})" if hostname else addr)
    return " ".join(parts)


__all__ = ["SYSTEM_PROMPT", "build_user_message"]
