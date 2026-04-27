// Type aliases mirroring the FastAPI response schemas.

export interface InvestigationSummary {
  id: string;
  incident_id: string;
  started_at: string | null;
  completed_at: string | null;
  incident_status: string | null;
  verdict: string | null;
  confidence: number | null;
  severity: string | null;
  mitre_techniques: string[];
  summary_excerpt: string | null;
  approval_status: string | null;
  review_status: string | null;
  writeback_status: string | null;
  inconclusive_reason: string | null;
  total_cost_usd: number | null;
}

export interface InvestigationListResponse {
  items: InvestigationSummary[];
  next_cursor: string | null;
}

export interface MitreTechnique {
  technique_id: string;
  name: string | null;
  tactic_ids: string[];
}

export interface InvestigationDetail {
  id: string;
  tenant_id: string;
  incident_id: string;
  incident_status: string | null;
  siem_notable_id: string | null;
  siem_source: string | null;
  ocsf_normalized: Record<string, unknown> | null;
  langgraph_thread_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  verdict: string | null;
  confidence: number | null;
  severity: string | null;
  mitre_techniques: string[];
  mitre_resolved: MitreTechnique[];
  summary: string | null;
  review_notes: string | null;
  review_status: string | null;
  review_metadata: Record<string, unknown> | null;
  approval_status: string | null;
  approver_id: string | null;
  approval_notes: string | null;
  human_approved_by: string | null;
  human_approved_at: string | null;
  writeback_status: string | null;
  writeback_attempts: Array<Record<string, unknown>>;
  detection_rule_matches: Array<Record<string, unknown>>;
  inconclusive_reason: string | null;
  evidence_s3_key: string | null;
  total_input_tokens: number | null;
  total_output_tokens: number | null;
  total_cost_usd: number | null;
  ocsf_output: Record<string, unknown> | null;
  decision_submitted: boolean;
}

export interface TimelineEntry {
  id: number;
  actor: string | null;
  action: string | null;
  details: Record<string, unknown> | null;
  created_at: string | null;
}

export interface TimelineResponse {
  items: TimelineEntry[];
}

export interface AuditEntry {
  id: number;
  investigation_id: string | null;
  actor: string | null;
  action: string | null;
  details: Record<string, unknown> | null;
  content_hash: string | null;
  previous_hash: string | null;
  hash_scope: string | null;
  created_at: string | null;
  chain_ok: boolean;
}

export interface AuditPage {
  items: AuditEntry[];
  next_cursor: string | null;
}

export interface CheckpointSummary {
  checkpoint_id: string;
  parent_checkpoint_id: string | null;
  step: number | null;
  ts: string | null;
  node_writes: string[];
  state_keys: string[];
  has_interrupt: boolean;
}

export interface CheckpointList {
  items: CheckpointSummary[];
}

export interface CheckpointDetail {
  checkpoint_id: string;
  parent_checkpoint_id: string | null;
  step: number | null;
  ts: string | null;
  metadata: Record<string, unknown>;
  channel_values: Record<string, unknown>;
}

export interface EvidenceManifest {
  incident?: { ocsf?: Record<string, unknown> };
  triage_result?: Record<string, unknown>;
  agent_turns?: Array<Record<string, unknown>>;
  tool_calls?: Array<Record<string, unknown>>;
  draft_verdict?: Record<string, unknown>;
  review_notes?: Record<string, unknown> | string | null;
  mitre_techniques?: string[];
  rule_matches?: Array<Record<string, unknown>>;
  final_output?: { ocsf?: Record<string, unknown> };
  token_usage?: Record<string, unknown>;
  attempts?: Array<Record<string, unknown>>;
  [extra: string]: unknown;
}
