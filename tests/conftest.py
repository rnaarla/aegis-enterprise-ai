"""Shared pytest fixtures including a real session-scoped PostgreSQL 18 RLS cluster."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from enterprise_twin.pg_ephemeral import ephemeral_postgres_cluster


@pytest.fixture(scope="session")
def pg_rls_dsn() -> Iterator[str]:
    """Boot an isolated PostgreSQL 18 cluster over a `/tmp` Unix socket for kernel RLS tests."""
    with ephemeral_postgres_cluster("aegis_test_rls") as dsn:
        yield dsn
