"""Outer Composition Root (`Dependency Injection / Inversion of Control`) for ASGI Hosting."""

from __future__ import annotations

from runtime_host.bootstrap import create_service_app_from_env

__all__ = ["create_service_app_from_env"]
