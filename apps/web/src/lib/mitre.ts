// Static MITRE ATT&CK Enterprise tactic taxonomy used by the heatmap.
// Mirrors the canonical 14-tactic Enterprise matrix; the seed table
// (`mitre_techniques`) carries technique→tactic mappings, but the order
// of tactic columns in the UI is fixed here.

export interface MitreTactic {
  id: string;
  shortName: string;
  name: string;
}

export const ENTERPRISE_TACTICS: MitreTactic[] = [
  { id: "TA0043", shortName: "recon", name: "Reconnaissance" },
  { id: "TA0042", shortName: "rdev", name: "Resource Development" },
  { id: "TA0001", shortName: "init", name: "Initial Access" },
  { id: "TA0002", shortName: "exec", name: "Execution" },
  { id: "TA0003", shortName: "persist", name: "Persistence" },
  { id: "TA0004", shortName: "privesc", name: "Privilege Escalation" },
  { id: "TA0005", shortName: "evade", name: "Defense Evasion" },
  { id: "TA0006", shortName: "creds", name: "Credential Access" },
  { id: "TA0007", shortName: "discover", name: "Discovery" },
  { id: "TA0008", shortName: "lateral", name: "Lateral Movement" },
  { id: "TA0009", shortName: "collect", name: "Collection" },
  { id: "TA0011", shortName: "c2", name: "Command and Control" },
  { id: "TA0010", shortName: "exfil", name: "Exfiltration" },
  { id: "TA0040", shortName: "impact", name: "Impact" },
];

export const TACTIC_BY_ID: Record<string, MitreTactic> = Object.fromEntries(
  ENTERPRISE_TACTICS.map((t) => [t.id, t]),
);

export function attackUrl(techniqueId: string): string {
  // T1059.001 → https://attack.mitre.org/techniques/T1059/001/
  const [base, sub] = techniqueId.split(".");
  if (sub) {
    return `https://attack.mitre.org/techniques/${base}/${sub}/`;
  }
  return `https://attack.mitre.org/techniques/${base}/`;
}
