/**
 * Project 12 (V2): Admin Portal Client SDK, Canary/Explain/WORM APIs & Flamegraph Analyzer.
 */

import type {
  CanaryStatusView,
  CriticalPathBottleneck,
  DepartmentROICard,
  MaskedConnectorSecretView,
  OTelSpanRaw,
  PolicyExplainInput,
  PolicyExplainPlanView,
  PromptVersionView,
  TraceWaterfallNode,
  WormAuditBundleView,
} from "./types.ts";

export class ControlPlaneHttpError extends Error {
  public readonly statusCode: number;
  public readonly payload: unknown;

  public constructor(statusCode: number, message: string, payload: unknown) {
    super(message);
    this.name = "ControlPlaneHttpError";
    this.statusCode = statusCode;
    this.payload = payload;
  }
}

export class AegisAdminPortalClient {
  private readonly baseUrl: string;
  private readonly getDelegatedJwt: () => string;

  public constructor(baseUrl: string, getDelegatedJwt: () => string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.getDelegatedJwt = getDelegatedJwt;
  }

  public async createPromptDraft(systemPrompt: string): Promise<PromptVersionView> {
    return this.requestJson<PromptVersionView>("/v1/admin/prompts", {
      method: "POST",
      body: JSON.stringify({ system_prompt: systemPrompt }),
    });
  }

  public async promotePromptVersion(versionId: string): Promise<PromptVersionView> {
    return this.requestJson<PromptVersionView>(
      `/v1/admin/prompts/${encodeURIComponent(versionId)}/promote`,
      { method: "POST" },
    );
  }

  public async configureCanary(
    canaryVersionId: string,
    weightPct: number,
  ): Promise<CanaryStatusView> {
    return this.requestJson<CanaryStatusView>("/v1/admin/canary", {
      method: "POST",
      body: JSON.stringify({
        canary_version_id: canaryVersionId,
        weight_pct: weightPct,
      }),
    });
  }

  public async explainPolicyAccess(input: PolicyExplainInput): Promise<PolicyExplainPlanView> {
    return this.requestJson<PolicyExplainPlanView>("/v1/admin/policy/explain", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  public async exportWormAuditBundle(): Promise<WormAuditBundleView> {
    return this.requestJson<WormAuditBundleView>("/v1/admin/audit/worm-export", {
      method: "GET",
    });
  }

  public async rotateConnectorSecret(
    connectorName: string,
    rawSecretValue: string,
  ): Promise<MaskedConnectorSecretView> {
    return this.requestJson<MaskedConnectorSecretView>("/v1/admin/secrets", {
      method: "POST",
      body: JSON.stringify({
        connector_name: connectorName,
        raw_secret_value: rawSecretValue,
      }),
    });
  }

  public async fetchTraceSpans(): Promise<readonly OTelSpanRaw[]> {
    return this.requestJson<readonly OTelSpanRaw[]>("/v1/admin/traces", {
      method: "GET",
    });
  }

  private async requestJson<T>(path: string, init: RequestInit): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${this.getDelegatedJwt()}`);
    headers.set("Content-Type", "application/json");

    const resp = await fetch(`${this.baseUrl}${path}`, { ...init, headers });
    const body: unknown = await resp.json();
    if (!resp.ok) {
      throw new ControlPlaneHttpError(
        resp.status,
        `Control plane request to ${path} failed with HTTP ${resp.status}`,
        body,
      );
    }
    return body as T;
  }
}

/**
 * Reconstructs hierarchical OpenTelemetry waterfall trees from flat span records.
 */
export function buildTraceWaterfall(spans: readonly OTelSpanRaw[]): readonly TraceWaterfallNode[] {
  if (spans.length === 0) {
    return [];
  }
  const maxDuration = Math.max(0.001, ...spans.map((s) => s.duration_ms));

  const byParent = new Map<string | null, OTelSpanRaw[]>();
  const spanIds = new Set(spans.map((s) => s.span_id));

  for (const sp of spans) {
    const parentKey =
      sp.parent_span_id !== null && spanIds.has(sp.parent_span_id) ? sp.parent_span_id : null;
    const bucket = byParent.get(parentKey);
    if (bucket !== undefined) {
      bucket.push(sp);
    } else {
      byParent.set(parentKey, [sp]);
    }
  }

  const buildSubtree = (parentId: string | null, depth: number): readonly TraceWaterfallNode[] => {
    const children = byParent.get(parentId) ?? [];
    return children.map((sp): TraceWaterfallNode => {
      const subAttr = sp.attributes["aegis.sub"];
      const principal = typeof subAttr === "string" ? subAttr : "system";
      const pct = Math.min(
        100,
        Math.max(1, Number(((sp.duration_ms / maxDuration) * 100).toFixed(2))),
      );
      return {
        span_id: sp.span_id,
        name: sp.name,
        depth,
        duration_ms: sp.duration_ms,
        width_pct: pct,
        security_principal: principal,
        children: buildSubtree(sp.span_id, depth + 1),
      };
    });
  };

  return buildSubtree(null, 0);
}

/**
 * Computes exclusive (`self`) span duration (`total_duration - sum(child_durations)`) to surface
 * true critical-path bottlenecks in O(N log N) time.
 */
export function analyzeCriticalPathBottlenecks(
  spans: readonly OTelSpanRaw[],
): readonly CriticalPathBottleneck[] {
  if (spans.length === 0) {
    return [];
  }
  const childSumByParent = new Map<string, number>();
  let totalRootMs = 0;
  const spanIdSet = new Set(spans.map((s) => s.span_id));

  for (const sp of spans) {
    if (sp.parent_span_id !== null && spanIdSet.has(sp.parent_span_id)) {
      const prev = childSumByParent.get(sp.parent_span_id) ?? 0;
      childSumByParent.set(sp.parent_span_id, prev + sp.duration_ms);
    } else {
      totalRootMs += sp.duration_ms;
    }
  }

  const denom = Math.max(0.001, totalRootMs);
  const bottlenecks = spans.map((sp): CriticalPathBottleneck => {
    const childMs = childSumByParent.get(sp.span_id) ?? 0;
    const selfMs = Math.max(0, Number((sp.duration_ms - childMs).toFixed(3)));
    return {
      span_id: sp.span_id,
      name: sp.name,
      self_duration_ms: selfMs,
      share_of_trace_pct: Number(((selfMs / denom) * 100).toFixed(2)),
    };
  });

  return [...bottlenecks].sort((a, b) => b.self_duration_ms - a.self_duration_ms);
}

/**
 * Computes executive FinOps summary totals across all tenant departments.
 */
export function summarizeTenantROI(cards: readonly DepartmentROICard[]): {
  readonly totalSpendUsd: number;
  readonly totalNetRoiUsd: number;
  readonly totalHoursSaved: number;
  readonly overallMultiple: number;
} {
  let spend = 0;
  let gross = 0;
  let netRoi = 0;
  let hours = 0;

  for (const card of cards) {
    spend += card.total_ai_spend_usd;
    gross += card.gross_productivity_value_usd;
    netRoi += card.net_roi_usd;
    hours += card.net_hours_saved;
  }

  return {
    totalSpendUsd: Number(spend.toFixed(4)),
    totalNetRoiUsd: Number(netRoi.toFixed(2)),
    totalHoursSaved: Number(hours.toFixed(2)),
    overallMultiple: spend > 0 ? Number((gross / spend).toFixed(2)) : 0,
  };
}
