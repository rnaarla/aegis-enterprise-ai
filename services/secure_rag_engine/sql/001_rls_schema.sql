-- =============================================================================
-- Aegis Enterprise AI — Project 4 (V2): Kernel-Enforced Transitive Zanzibar RLS
-- Target: PostgreSQL 16 / 17 / 18+
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app_runtime') THEN
        CREATE ROLE aegis_app_runtime NOLOGIN NOBYPASSRLS;
    END IF;
END
$$;

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

-- Transitive Group / Deal-Room Hierarchy (`parent_group` includes `child_id`)
CREATE TABLE IF NOT EXISTS rebac_group_hierarchy (
    tenant_id    TEXT NOT NULL,
    parent_group TEXT NOT NULL,
    child_type   TEXT NOT NULL CHECK (child_type IN ('user', 'group')),
    child_id     TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, parent_group, child_type, child_id)
);

CREATE INDEX IF NOT EXISTS idx_rebac_hierarchy_child
    ON rebac_group_hierarchy (tenant_id, child_type, child_id, parent_group);

-- Cycle-safe, depth-bounded (<= 8 hops) transitive group closure evaluated inside Postgres kernel
CREATE OR REPLACE FUNCTION aegis_effective_groups(
    p_tenant TEXT,
    p_sub TEXT,
    p_seed_groups TEXT[]
)
RETURNS TEXT[]
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    WITH RECURSIVE group_walk(grp, depth, visited) AS (
        SELECT g, 1, ARRAY[g]
        FROM unnest(COALESCE(p_seed_groups, ARRAY[]::TEXT[])) AS g
        WHERE g <> ''
        UNION
        SELECT h.parent_group, 1, ARRAY[h.parent_group]
        FROM rebac_group_hierarchy h
        WHERE h.tenant_id = p_tenant
          AND h.child_type = 'user'
          AND h.child_id = p_sub
        UNION
        SELECT h2.parent_group, gw.depth + 1, gw.visited || h2.parent_group
        FROM group_walk gw
        JOIN rebac_group_hierarchy h2
          ON h2.tenant_id = p_tenant
         AND h2.child_type = 'group'
         AND h2.child_id = gw.grp
        WHERE gw.depth < 8
          AND NOT (h2.parent_group = ANY(gw.visited))
    )
    SELECT COALESCE(array_agg(DISTINCT grp), ARRAY[]::TEXT[])
    FROM group_walk;
$$;

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

GRANT USAGE ON SCHEMA public TO aegis_app_runtime;
GRANT SELECT ON rag_chunks TO aegis_app_runtime;
GRANT SELECT ON rebac_tuples TO aegis_app_runtime;
GRANT SELECT ON rebac_group_hierarchy TO aegis_app_runtime;
GRANT EXECUTE ON FUNCTION aegis_cosine_similarity(DOUBLE PRECISION[], DOUBLE PRECISION[]) TO aegis_app_runtime;
GRANT EXECUTE ON FUNCTION aegis_effective_groups(TEXT, TEXT, TEXT[]) TO aegis_app_runtime;

ALTER TABLE rag_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE rag_chunks FORCE ROW LEVEL SECURITY;

-- Policy 1 (PERMISSIVE): Positive Transitive Zanzibar ReBAC Grant (direct user OR transitive group)
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
                          aegis_effective_groups(
                              COALESCE(NULLIF(current_setting('aegis.tenant_id', true), ''), '__NO_TENANT__'),
                              COALESCE(NULLIF(current_setting('aegis.sub', true), ''), '__NO_USER__'),
                              string_to_array(COALESCE(current_setting('aegis.groups', true), ''), ',')
                          )
                      )
                  )
              )
        )
    );

-- Policy 2 (RESTRICTIVE): Tenant Isolation + MAC Clearance + Transitive Ethical-Wall DENY
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
                          aegis_effective_groups(
                              COALESCE(NULLIF(current_setting('aegis.tenant_id', true), ''), '__NO_TENANT__'),
                              COALESCE(NULLIF(current_setting('aegis.sub', true), ''), '__NO_USER__'),
                              string_to_array(COALESCE(current_setting('aegis.groups', true), ''), ',')
                          )
                      )
                  )
              )
        )
    );

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
