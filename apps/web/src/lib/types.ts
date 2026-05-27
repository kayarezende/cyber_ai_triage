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

// ---- wk-10 admin panel

export type LlmRole =
  | "triage"
  | "investigation"
  | "review"
  | "summarize"
  | "entity_extraction";

export interface LlmRoleConfig {
  role: LlmRole;
  primary_model: string;
  fallback_chain: string[];
  max_tokens: number;
  temperature: number;
  timeout_seconds: number;
  enabled: boolean;
}

export interface LlmRoleListResponse {
  items: LlmRoleConfig[];
}

export type LlmProvider = "openrouter" | "groq" | "gemini" | "anthropic";

export interface ProviderKeyStatus {
  provider: LlmProvider;
  is_set: boolean;
  key_last4: string | null;
  updated_at: string | null;
}

export interface ProviderKeyListResponse {
  items: ProviderKeyStatus[];
}

export interface HitlPolicy {
  id: string;
  tenant_id: string | null;
  name: string;
  rule_expression: Record<string, unknown>;
  priority: number;
  enabled: boolean;
}

export interface HitlPolicyListResponse {
  items: HitlPolicy[];
}

export interface TenantBudgets {
  max_concurrent_investigations: number | null;
  monthly_llm_budget_usd: number | null;
  per_investigation_budget_usd: number | null;
  per_investigation_token_cap: number | null;
}

export type WritebackMode = "dual" | "hec_only";

export interface SplunkConfig {
  splunk_host: string | null;
  writeback_mode: WritebackMode;
  has_management_token: boolean;
  has_hec_token: boolean;
}

export type UserRole = "analyst" | "admin";

export interface TenantUser {
  id: string;
  email: string;
  role: UserRole;
  entra_oid: string | null;
  created_at: string | null;
}

export interface TenantUserListResponse {
  items: TenantUser[];
}

export interface UsageRow {
  month: string;
  role: string;
  model_requested: string;
  attempts: number;
  successes: number;
  failures: number;
  input_tokens: number;
  output_tokens: number;
  cached_tokens: number;
  cost_usd: number;
}

export interface UsageStatusBreakdown {
  status: string;
  count: number;
}

export interface UsageSummary {
  months_back: number;
  total_attempts: number;
  total_successes: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_cached_tokens: number;
  total_cost_usd: number;
  rows: UsageRow[];
  by_status: UsageStatusBreakdown[];
}
