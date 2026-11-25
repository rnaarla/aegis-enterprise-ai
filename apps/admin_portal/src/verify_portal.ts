import {
  AegisAdminPortalClient,
  ControlPlaneHttpError,
  buildTraceWaterfall,
  summarizeTenantROI,
} from "./index.ts";
import type { DepartmentROICard, OTelSpanRaw } from "./types.ts";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

async function runTypeScriptPortalSuite(): Promise<void> {
  // 1. Unit test OTel Waterfall Tree Builder (empty, orphan, and nested spans)
  assert(buildTraceWaterfall([]).length === 0, "Empty span list returns empty waterfall");

  const sampleSpans: readonly OTelSpanRaw[] = [
    {
      trace_id: "tr-1",
      span_id: "root-span",
      parent_span_id: "missing-external-parent",
      name: "aegis.oauth.token_exchange",
      duration_ms: 40,
      attributes: { "aegis.sub": "elena.vance" },
    },
    {
      trace_id: "tr-1",
      span_id: "child-span",
      parent_span_id: "root-span",
      name: "gen_ai.retrieval",
      duration_ms: 20,
      attributes: { "gen_ai.retrieval.top_k": 5 },
    },
  ];

  const tree = buildTraceWaterfall(sampleSpans);
  assert(tree.length === 1, "Single root node reconstructed");
  assert(tree[0]?.security_principal === "elena.vance", "Extracted principal attribute");
  assert(tree[0]?.children[0]?.width_pct === 50, "Computed child waterfall width percentage");
  assert(tree[0]?.children[0]?.security_principal === "system", "Fallback system principal");

  // 2. Unit test Tenant FinOps ROI Aggregator (zero-spend & multi-department)
  assert(summarizeTenantROI([]).overallMultiple === 0, "Zero spend handles division safely");

  const cards: readonly DepartmentROICard[] = [
    {
      tenant_id: "meridian-fin",
      cost_center: "CORP_DEV",
      total_events: 10,
      verified_resolutions: 9,
      human_escalations: 1,
      failed_retries: 0,
      total_tokens: 200000,
      retry_waste_usd: 0,
      total_ai_spend_usd: 2.5,
      net_hours_saved: 6.4,
      gross_productivity_value_usd: 1415.0,
      net_roi_usd: 1412.5,
      roi_multiple: 566.0,
    },
  ];
  const summary = summarizeTenantROI(cards);
  assert(summary.totalNetRoiUsd === 1412.5 && summary.overallMultiple === 566, "ROI summary math");

  // 3. Integration test AegisAdminPortalClient HTTP transport & 422 Shadow Replay Gate error
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const hdrs = new Headers(init?.headers);
      assert(hdrs.get("Authorization") === "Bearer delegated-jwt-xyz", "Bearer header attached");

      if (url.endsWith("/v1/admin/prompts") && init?.method === "POST") {
        return new Response(
          JSON.stringify({
            version_id: "prompt-v2",
            version_number: 2,
            system_prompt: "test",
            author_sub: "david.kim",
            created_at: "2026-11-25T00:00:00Z",
            is_active_production: false,
            diff_from_previous: "+test",
            last_shadow_replay: null,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }

      if (url.endsWith("/v1/admin/prompts/prompt-bad/promote")) {
        return new Response(
          JSON.stringify({ error: "shadow_replay_gate_failed", policy_violations: 125 }),
          { status: 422, headers: { "Content-Type": "application/json" } },
        );
      }

      if (url.endsWith("/v1/admin/secrets")) {
        return new Response(
          JSON.stringify({
            connector_name: "sap-prd",
            masked_preview: "••••••••9921",
            ciphertext_sha256: "abc",
            updated_by: "david.kim",
            updated_at: "2026-11-25T00:00:00Z",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }

      return new Response(JSON.stringify(sampleSpans), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new AegisAdminPortalClient("https://cp.meridian.fin/", () => "delegated-jwt-xyz");
    const draft = await client.createPromptDraft("New system prompt");
    assert(draft.version_id === "prompt-v2", "Draft created");

    const secret = await client.rotateConnectorSecret("sap-prd", "raw-secret-9921");
    assert(secret.masked_preview === "••••••••9921", "Connector secret masked");

    const spans = await client.fetchTraceSpans();
    assert(spans.length === 2, "Fetched OTel spans");

    let caughtGateError = false;
    try {
      await client.promotePromptVersion("prompt-bad");
    } catch (err: unknown) {
      if (err instanceof ControlPlaneHttpError && err.statusCode === 422) {
        caughtGateError = true;
      }
    }
    assert(caughtGateError, "422 Shadow Replay Gate rejection surfaced as ControlPlaneHttpError");
  } finally {
    globalThis.fetch = originalFetch;
  }
}

await runTypeScriptPortalSuite();
