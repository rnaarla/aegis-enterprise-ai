-- Project 9: Production ClickHouse OLAP Schema for OpenTelemetry `gen_ai.*` FinOps
CREATE TABLE IF NOT EXISTS gen_ai_telemetry_events (
    event_id               String,
    occurred_at            DateTime64(3, 'UTC'),
    tenant_id              LowCardinality(String),
    cost_center            LowCardinality(String),
    workflow_type          LowCardinality(String),
    human_subject          String,
    actor_spiffe_id        String,
    model_id               LowCardinality(String),
    uncached_input_tokens  UInt32,
    cached_input_tokens    UInt32,
    reasoning_tokens       UInt32,
    output_tokens          UInt32,
    external_api_cost_usd  Float64,
    is_retry_attempt       UInt8,
    outcome                Enum8('VERIFIED_RESOLVED' = 1, 'HUMAN_ESCALATED' = 2, 'FAILED_RETRY' = 3)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, cost_center, workflow_type, occurred_at);
