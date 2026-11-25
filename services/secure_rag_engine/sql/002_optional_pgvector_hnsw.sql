-- Optional acceleration script applied automatically on clusters with pgvector >= 0.8.0
-- Enables iterative HNSW graph traversal so restrictive RLS pre-filters never starve top-K recall.
CREATE EXTENSION IF NOT EXISTS vector;

ALTER TABLE rag_chunks
    ADD COLUMN IF NOT EXISTS embedding_vec vector(64);

CREATE INDEX IF NOT EXISTS idx_rag_chunks_hnsw
    ON rag_chunks USING hnsw (embedding_vec vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);
