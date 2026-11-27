/**
 * Project 12 (V2): Strictly-typed contracts for the Self-Serve Customer IT Admin Portal.
 * Mirrors `services/admin_control_plane/` and `services/finops_telemetry/`.
 */

export interface ShadowReplayGateSummary {
  readonly prompt_version_id: string;
  readonly total_tickets: number;
  readonly passed_tickets: number;
  readonly trajectory_accuracy: number;
  readonly accuracy_ci99_lower?: number;
  readonly slice_accuracies?: Readonly<Record<string, number>>;
  readonly policy_violations: number;
  readonly temporal_leakage_detected: boolean;
  readonly live_erp_writes_attempted: number;
  readonly release_gate_passed: boolean;
}

export interface PromptVersionView {
  readonly version_id: string;
  readonly version_number: number;
  readonly system_prompt: string;
  readonly author_sub: string;
  readonly created_at: string;
  readonly is_active_production: boolean;
  readonly diff_from_previous: string;
  readonly last_shadow_replay: ShadowReplayGateSummary | null;
}

export interface CanaryStatusView {
  readonly baseline_version_id: string;
  readonly canary_version_id: string | null;
  readonly canary_weight_pct: number;
  readonly observed_samples: number;
  readonly observed_errors: number;
  readonly observed_error_rate: number;
  readonly auto_rolled_back: boolean;
  readonly last_rollback_reason: string | null;
}

export interface PolicyExplainStepView {
  readonly gate_name: string;
  readonly passed: boolean;
  readonly explanation: string;
}

export interface PolicyExplainPlanView {
  readonly decision: "ALLOW" | "DENY";
  readonly subject_id: string;
  readonly document_id: string;
  readonly effective_groups: readonly string[];
  readonly steps: readonly PolicyExplainStepView[];
}

export interface PolicyExplainInput {
  readonly subject_id: string;
  readonly direct_groups: readonly string[];
  readonly subject_clearance: number;
  readonly document_id: string;
  readonly document_clearance_required: number;
}

export interface WormAuditBundleView {
  readonly tenant_id: string;
  readonly worm_mode: "COMPLIANCE";
  readonly worm_retain_until: string;
  readonly record_count: number;
  readonly chain_tip_sha256: string;
  readonly jws_attestation: string;
}

export interface MaskedConnectorSecretView {
  readonly connector_name: string;
  readonly masked_preview: string;
  readonly ciphertext_sha256: string;
  readonly updated_by: string;
  readonly updated_at: string;
}

export interface OTelSpanRaw {
  readonly trace_id: string;
  readonly span_id: string;
  readonly parent_span_id: string | null;
  readonly name: string;
  readonly duration_ms: number;
  readonly attributes: Readonly<Record<string, string | number | boolean>>;
}

export interface TraceWaterfallNode {
  readonly span_id: string;
  readonly name: string;
  readonly depth: number;
  readonly duration_ms: number;
  readonly width_pct: number;
  readonly security_principal: string;
  readonly children: readonly TraceWaterfallNode[];
}

export interface CriticalPathBottleneck {
  readonly span_id: string;
  readonly name: string;
  readonly self_duration_ms: number;
  readonly share_of_trace_pct: number;
}

export interface DepartmentROICard {
  readonly tenant_id: string;
  readonly cost_center: string;
  readonly total_events: number;
  readonly verified_resolutions: number;
  readonly human_escalations: number;
  readonly failed_retries: number;
  readonly total_tokens: number;
  readonly retry_waste_usd: number;
  readonly total_ai_spend_usd: number;
  readonly net_hours_saved: number;
  readonly gross_productivity_value_usd: number;
  readonly net_roi_usd: number;
  readonly roi_multiple: number;
}
