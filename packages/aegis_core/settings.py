"""12-Factor immutable environment configuration (`pydantic-settings`) for Aegis services."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AegisServiceSettings(BaseSettings):
    """Typed, fail-fast startup settings shared across control-plane and data-plane workers."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        frozen=True,
        extra="ignore",
    )

    environment: str = Field(default="production", min_length=2)
    tenant_id: str = Field(default="meridian-fin", min_length=2)
    issuer_url: str = Field(default="https://auth.aegis.meridian.fin")
    audience: str = Field(default="aegis-data-plane")
    max_token_ttl_seconds: int = Field(default=300, ge=30, le=300)
    db_pool_max_connections: int = Field(default=16, ge=1, le=256)
    db_statement_timeout_ms: int = Field(default=2_000, ge=100, le=60_000)
    circuit_failure_threshold: int = Field(default=5, ge=1, le=100)
    circuit_recovery_seconds: float = Field(default=15.0, gt=0.0)
