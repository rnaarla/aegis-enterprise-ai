-- =============================================================================
-- Aegis Enterprise AI — Project 4: Kernel-Enforced Row-Level Secure RAG Schema
-- Target: PostgreSQL 16 / 17 / 18+
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app_runtime') THEN
        CREATE ROLE aegis_app_runtime NOLOGIN NOBYPASSRLS;
    END IF;
END
$$;

-- Pure-SQL SIMD-friendly L2-normalized cosine similarity for zero-dependency portability
-- (Paired with optional 002_pgvector_hnsw.sql when pgvector C extension is loaded)
CREATE OR REPLACE FUNCTION aegis_cosine_similarity(a DOUBLE PRECISION[], b DOUBLE PRECISION[])
RETURNS DOUBLE PRECISION
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
STRICT
AS $$
    SELECT COALESCE(SUM(x * y), 0.0)
    FROM unnest(a, b) WITH ORDINALITY AS t(x, y, idx);
$$;

CREATE TABLE IF NOT EXISTS rebac_tuples (
    tenant_id    TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    relation     TEXT NOT NULL CHECK (relation IN ('viewer', 'editor', 'owner', 'ethical_wall_deny')),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'group')),
    subject_id   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, object_id, relation, subject_type, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_rebac_lookup
    ON rebac_tuples (tenant_id, object_id, relation, subject_type, subject_id);

CREATE TABLE IF NOT EXISTS rag_chunks (
    chunk_id            TEXT PRIMARY KEY,
    document_id         TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    title               TEXT NOT NULL,
    source_uri          TEXT NOT NULL,
    source_system       TEXT NOT NULL,
    page_or_record_ref  TEXT NOT NULL,
    classification      TEXT NOT NULL,
    clearance_required  INTEGER NOT NULL,
    department_owner    TEXT NOT NULL,
    content             TEXT NOT NULL,
    embedding           DOUBLE PRECISION[] NOT NULL,
    search_tsv          TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('english', COALESCE(title, '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(content, '')), 'B')
    ) STORED,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rag_chunks_tenant_doc
    ON rag_chunks (tenant_id, document_id, clearance_required);

CREATE INDEX IF NOT EXISTS idx_rag_chunks_tsv
    ON rag_chunks USING GIN (search_tsv);

-- Grant minimal SELECT-only permissions to unprivileged runtime role
GRANT USAGE ON SCHEMA public TO aegis_app_runtime;
GRANT SELECT ON rag_chunks TO aegis_app_runtime;
GRANT SELECT ON rebac_tuples TO aegis_app_runtime;
GRANT EXECUTE ON FUNCTION aegis_cosine_similarity(DOUBLE PRECISION[], DOUBLE PRECISION[]) TO aegis_app_runtime;

-- =============================================================================
-- Kernel-Enforced Row-Level Security (FORCE RLS applies even to table owners)
-- =============================================================================
ALTER TABLE rag_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE rag_chunks FORCE ROW LEVEL SECURITY;

-- Policy 1 (PERMISSIVE): Positive Zanzibar ReBAC entitlement grant (user OR group)
DROP POLICY IF EXISTS aegis_rebac_positive_grant ON rag_chunks;
CREATE POLICY aegis_rebac_positive_grant ON rag_chunks
    AS PERMISSIVE
    FOR SELECT
    TO PUBLIC
    USING (
        EXISTS (
            SELECT 1
            FROM rebac_tuples rt
            WHERE rt.tenant_id = rag_chunks.tenant_id
              AND rt.object_id = rag_chunks.document_id
              AND rt.relation IN ('viewer', 'editor', 'owner')
              AND (
                  (
                      rt.subject_type = 'user'
                      AND rt.subject_id = COALESCE(NULLIF(current_setting('aegis.sub', true), ''), '__NO_USER__')
                  )
                  OR (
                      rt.subject_type = 'group'
                      AND rt.subject_id = ANY(
                          string_to_array(COALESCE(current_setting('aegis.groups', true), ''), ',')
                      )
                  )
              )
        )
    );

-- Policy 2 (RESTRICTIVE): Non-bypassable Mandatory Guardrails
-- Enforces Tenant Isolation + MAC Clearance Ceiling + Investment Banking Ethical Wall DENY
DROP POLICY IF EXISTS aegis_mandatory_zero_trust_guard ON rag_chunks;
CREATE POLICY aegis_mandatory_zero_trust_guard ON rag_chunks
    AS RESTRICTIVE
    FOR SELECT
    TO PUBLIC
    USING (
        tenant_id = COALESCE(NULLIF(current_setting('aegis.tenant_id', true), ''), '__NO_TENANT__')
        AND clearance_required <= COALESCE(
            NULLIF(current_setting('aegis.clearance', true), '')::integer,
            -1
        )
        AND NOT EXISTS (
            SELECT 1
            FROM rebac_tuples deny_rt
            WHERE deny_rt.tenant_id = rag_chunks.tenant_id
              AND deny_rt.object_id = rag_chunks.document_id
              AND deny_rt.relation = 'ethical_wall_deny'
              AND (
                  (
                      deny_rt.subject_type = 'user'
                      AND deny_rt.subject_id = COALESCE(NULLIF(current_setting('aegis.sub', true), ''), '__NO_USER__')
                  )
                  OR (
                      deny_rt.subject_type = 'group'
                      AND deny_rt.subject_id = ANY(
                          string_to_array(COALESCE(current_setting('aegis.groups', true), ''), ',')
                      )
                  )
              )
        )
    );

-- =============================================================================
-- Append-Only Per-Tenant Hash-Chained Audit Ledger with Kernel Immutability Trigger
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_ledger (
    sequence_id     BIGINT NOT NULL,
    occurred_at_iso TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    human_subject   TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    jti             TEXT,
    decision        TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'REVOKE')),
    detail_json     JSONB NOT NULL,
    prev_hash       CHAR(64) NOT NULL,
    entry_hash      CHAR(64) NOT NULL UNIQUE,
    PRIMARY KEY (tenant_id, sequence_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_ledger_tenant_seq_desc
    ON audit_ledger (tenant_id, sequence_id DESC);

CREATE OR REPLACE FUNCTION prevent_audit_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Security Violation: audit_ledger is cryptographically append-only (attempted %)', TG_OP
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_ledger_no_update_delete ON audit_ledger;
CREATE TRIGGER trg_audit_ledger_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_ledger
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_ledger_mutation();

DROP TRIGGER IF EXISTS trg_audit_ledger_no_truncate ON audit_ledger;
CREATE TRIGGER trg_audit_ledger_no_truncate
    BEFORE TRUNCATE ON audit_ledger
    FOR EACH STATEMENT
    EXECUTE FUNCTION prevent_audit_ledger_mutation();
