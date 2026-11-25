# =============================================================================
# Aegis Enterprise AI — Hardened Multi-Stage Non-Root Container Image (UID 65532)
# Supports zero-egress air-gapped execution (`HF_HUB_OFFLINE=1`, read-only rootfs)
# =============================================================================
FROM python:3.13-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY packages ./packages
COPY services ./services

RUN python -m venv /opt/aegis-venv && \
    /opt/aegis-venv/bin/pip install --no-cache-dir .

FROM python:3.13-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HUB_OFFLINE=1 \
    TIKTOKEN_CACHE_DIR=/opt/aegis/offline-cache \
    PATH="/opt/aegis-venv/bin:$PATH"

RUN groupadd -g 65532 nonroot && \
    useradd -u 65532 -g 65532 -d /nonexistent -s /usr/sbin/nologin nonroot && \
    mkdir -p /opt/aegis/offline-cache && \
    chown -R 65532:65532 /opt/aegis

COPY --from=builder --chown=65532:65532 /opt/aegis-venv /opt/aegis-venv
COPY --chown=65532:65532 packages /opt/aegis/packages
COPY --chown=65532:65532 services /opt/aegis/services
COPY --chown=65532:65532 apps/admin_portal/public /opt/aegis/apps/admin_portal/public

WORKDIR /opt/aegis
USER 65532:65532
EXPOSE 8080

ARG AEGIS_APP_FACTORY="sso_delegation_broker.app:create_broker_app"
ENV AEGIS_APP_FACTORY=${AEGIS_APP_FACTORY}

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]

CMD ["python", "-m", "uvicorn", "sso_delegation_broker.app:create_broker_app", "--host", "0.0.0.0", "--port", "8080"]
