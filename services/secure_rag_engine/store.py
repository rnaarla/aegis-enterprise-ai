"""PostgreSQL 18 `FORCE ROW LEVEL SECURITY` hybrid retrieval store with Transitive Zanzibar."""

from __future__ import annotations

from pathlib import Path

from aegis_core.db_pool import BoundedPostgresPool
from aegis_core.models import (
    DelegatedTokenClaims,
    DocumentChunk,
    DocumentClassification,
    ReBACGroupHierarchyEdge,
    ReBACTuple,
    ScoredChunk,
)
from aegis_core.ports import EmbeddingProviderPort

_SQL_DIR = Path(__file__).resolve().parent / "sql"
_SCHEMA_SQL_PATH = _SQL_DIR / "001_rls_schema.sql"


class PostgresRLSRetrievalStore:
    """Executes hybrid Dense + Lexical RRF search strictly under PostgreSQL `aegis_app_runtime` RLS."""

    def __init__(
        self,
        *,
        dsn: str,
        embedder: EmbeddingProviderPort,
        pool: BoundedPostgresPool | None = None,
    ) -> None:
        self._dsn = dsn
        self._embedder = embedder
        self._pool = pool if pool is not None else BoundedPostgresPool(dsn, max_connections=16)

    def apply_migrations(self) -> None:
        """Apply idempotent RLS schema, transitive closure SQL, `NOBYPASSRLS`, & audit triggers."""
        ddl = _SCHEMA_SQL_PATH.read_text(encoding="utf-8")
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(ddl)

    def ingest_group_hierarchy(self, edges: list[ReBACGroupHierarchyEdge]) -> int:
        """Upsert transitive Zanzibar group/deal-room hierarchy edges (`parent_group` -> `child_id`)."""
        if not edges:
            return 0
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            for edge in edges:
                cur.execute(
                    """
                    INSERT INTO rebac_group_hierarchy (tenant_id, parent_group, child_type, child_id)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (tenant_id, parent_group, child_type, child_id) DO NOTHING
                    """,
                    (edge.tenant_id, edge.parent_group, edge.child_type, edge.child_id),
                )
        return len(edges)

    def ingest_chunks(
        self,
        chunks: list[DocumentChunk],
        rebac_tuples: list[ReBACTuple],
    ) -> int:
        """Embed and upsert document chunks alongside Zanzibar ReBAC access tuples."""
        if not chunks and not rebac_tuples:
            return 0

        embeddings = self._embedder.embed_texts([c.content for c in chunks]) if chunks else []
        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            for tup in rebac_tuples:
                cur.execute(
                    """
                    INSERT INTO rebac_tuples (tenant_id, object_id, relation, subject_type, subject_id)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, object_id, relation, subject_type, subject_id) DO NOTHING
                    """,
                    (
                        tup.tenant_id,
                        tup.object_id,
                        tup.relation,
                        tup.subject_type,
                        tup.subject_id,
                    ),
                )

            for chunk, vec in zip(chunks, embeddings, strict=True):
                cur.execute(
                    """
                    INSERT INTO rag_chunks (
                        chunk_id, document_id, tenant_id, title, source_uri,
                        source_system, page_or_record_ref, classification,
                        clearance_required, department_owner, content, embedding
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (chunk_id) DO UPDATE SET
                        title = EXCLUDED.title,
                        content = EXCLUDED.content,
                        classification = EXCLUDED.classification,
                        clearance_required = EXCLUDED.clearance_required,
                        embedding = EXCLUDED.embedding
                    """,
                    (
                        chunk.chunk_id,
                        chunk.document_id,
                        chunk.tenant_id,
                        chunk.title,
                        chunk.source_uri,
                        chunk.source_system,
                        chunk.page_or_record_ref,
                        chunk.classification.value,
                        int(chunk.clearance_required),
                        chunk.department_owner,
                        chunk.content,
                        vec,
                    ),
                )
        return len(chunks)

    def retrieve_authorized(
        self,
        claims: DelegatedTokenClaims,
        query: str,
        top_k: int,
    ) -> tuple[list[ScoredChunk], str, bool]:
        """Bind verified JWT identity into PostgreSQL transaction GUCs and run hybrid RRF query."""
        query_vec = self._embedder.embed_texts([query])[0]
        groups_csv = ",".join(claims.groups)

        with self._pool.connection() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute(
                "SELECT set_config('statement_timeout', %s, true)",
                (f"{self._pool.statement_timeout_ms}ms",),
            )
            cur.execute("SET LOCAL ROLE aegis_app_runtime")
            cur.execute(
                """
                SELECT
                    set_config('aegis.tenant_id', %s, true),
                    set_config('aegis.sub', %s, true),
                    set_config('aegis.groups', %s, true),
                    set_config('aegis.clearance', %s, true)
                """,
                (
                    claims.tenant_id,
                    claims.sub,
                    groups_csv,
                    str(int(claims.clearance)),
                ),
            )

            cur.execute(
                """
                SELECT
                    current_user,
                    (SELECT relrowsecurity AND relforcerowsecurity
                     FROM pg_class WHERE relname = 'rag_chunks')
                """
            )
            role_row = cur.fetchone()
            active_role = str(role_row[0]) if role_row else "unknown"
            rls_forced = bool(role_row[1]) if role_row else False

            cur.execute(
                """
                WITH visible AS (
                    SELECT
                        chunk_id,
                        document_id,
                        title,
                        source_uri,
                        source_system,
                        page_or_record_ref,
                        classification,
                        content,
                        aegis_cosine_similarity(embedding, %s::double precision[]) AS dense_score,
                        ts_rank_cd(search_tsv, websearch_to_tsquery('english', %s)) AS lexical_score
                    FROM rag_chunks
                ),
                ranked AS (
                    SELECT
                        *,
                        ROW_NUMBER() OVER (ORDER BY dense_score DESC, chunk_id ASC) AS dense_rank,
                        ROW_NUMBER() OVER (ORDER BY lexical_score DESC, dense_score DESC, chunk_id ASC) AS lex_rank
                    FROM visible
                )
                SELECT
                    chunk_id,
                    document_id,
                    title,
                    source_uri,
                    source_system,
                    page_or_record_ref,
                    classification,
                    content,
                    dense_score,
                    lexical_score,
                    (1.0 / (60.0 + dense_rank)) + (1.0 / (60.0 + lex_rank)) AS rrf_score
                FROM ranked
                ORDER BY rrf_score DESC, dense_score DESC
                LIMIT %s
                """,
                (query_vec, query, top_k),
            )
            rows = cur.fetchall()

        results: list[ScoredChunk] = [
            ScoredChunk(
                chunk_id=str(r[0]),
                document_id=str(r[1]),
                title=str(r[2]),
                source_uri=str(r[3]),
                source_system=str(r[4]),
                page_or_record_ref=str(r[5]),
                classification=DocumentClassification(str(r[6])),
                content=str(r[7]),
                dense_score=round(float(r[8]), 6),
                lexical_score=round(float(r[9]), 6),
                rrf_score=round(float(r[10]), 6),
            )
            for r in rows
        ]
        return results, active_role, rls_forced
