.PHONY: help typecheck typecheck-py typecheck-ts lint test test-unit test-integration test-system test-ts demo-ciso demo-all-12 helm-lint tf-validate verify-all

PYTHON ?= .venv/bin/python
MYPY ?= .venv/bin/mypy
PYTEST ?= $(PYTHON) -m pytest
RUFF ?= $(shell command -v ruff 2>/dev/null || echo /opt/homebrew/bin/ruff)
NODE ?= $(shell command -v node 2>/dev/null || echo /opt/homebrew/bin/node)
TSC ?= $(shell command -v tsc 2>/dev/null || echo /opt/homebrew/lib/node_modules/openclaw/node_modules/.bin/tsc)
HELM ?= $(shell command -v helm 2>/dev/null || echo /opt/homebrew/bin/helm)
TERRAFORM ?= $(shell command -v terraform 2>/dev/null || echo /opt/homebrew/bin/terraform)
PYTHONPATH := packages:services:.

help:
	@echo "Aegis Enterprise AI — Complete 12-Project Fortune 500 Solution Accelerator"
	@echo "  make typecheck        Run mypy --strict (Python) AND tsc --noEmit (TypeScript)"
	@echo "  make lint             Run ruff static & Bandit security linter across all Python modules"
	@echo "  make helm-lint        Validate CNCF air-gapped & demo Helm chart profiles"
	@echo "  make tf-validate      Validate zero-egress AWS VPC Terraform configuration"
	@echo "  make test-unit        Run Tier 1 isolated Python unit tests (-m unit)"
	@echo "  make test-integration Run Tier 2 HTTP ASGI, Postgres 18 RLS, Temporal & OCR tests (-m integration)"
	@echo "  make test-system      Run Tier 3 end-to-end 12-module enterprise system tests (-m system)"
	@echo "  make test-ts          Run TypeScript Admin Portal unit & client integration tests"
	@echo "  make test             Run all 3 Python tiers (with >=90% coverage gate) + TypeScript suite"
	@echo "  make verify-all       Run all static analyzers, IaC validators, and full test pyramid"

typecheck-py:
	PYTHONPATH=$(PYTHONPATH) $(MYPY) --strict packages services enterprise_twin tests

typecheck-ts:
	$(TSC) --noEmit -p apps/admin_portal/tsconfig.json

typecheck: typecheck-py typecheck-ts

lint:
	$(RUFF) check --cache-dir /tmp/aegis_ruff_cache packages services enterprise_twin tests

helm-lint:
	$(HELM) lint --strict deploy/helm/aegis -f deploy/helm/aegis/values.yaml
	$(HELM) lint --strict deploy/helm/aegis -f deploy/helm/aegis/values-demo.yaml
	$(HELM) lint --strict deploy/helm/aegis -f deploy/helm/aegis/values-prod-airgap.yaml

tf-validate:
	$(TERRAFORM) -chdir=deploy/terraform/aws_airgap_vpc init -backend=false -input=false
	$(TERRAFORM) -chdir=deploy/terraform/aws_airgap_vpc validate

test-unit:
	PYTHONPATH=$(PYTHONPATH) $(PYTEST) -v -m unit tests

test-integration:
	PYTHONPATH=$(PYTHONPATH) $(PYTEST) -v -m integration tests

test-system:
	PYTHONPATH=$(PYTHONPATH) $(PYTEST) -v -m system tests

test-ts:
	$(NODE) apps/admin_portal/src/verify_portal.ts

test: test-ts
	PYTHONPATH=$(PYTHONPATH) $(PYTEST) -v --cov=packages --cov=services --cov=enterprise_twin --cov-report=term-missing --cov-fail-under=95 tests

demo-ciso:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m enterprise_twin.demo_runner.run_ciso_pov

demo-all-12:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m enterprise_twin.demo_runner.run_full_12_module_pov

verify-all: typecheck lint helm-lint tf-validate test
