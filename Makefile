# Cross-platform entry points. The README's PowerShell commands are exact for
# Windows; these are the equivalent on macOS and Linux, where `npm.cmd` and
# `.venv/Scripts/` do not exist.
#
#   make setup     first run: dependencies, services, schema, demo data
#   make dev       start the wallet
#   make verify    everything CI runs, in CI's order
#   make security  the security tooling on its own
#   make clean     stop services, keep the data volumes

SHELL := /bin/bash
PY := .venv/bin/python

.PHONY: setup dev verify security lab clean reset help

help:
	@grep -E '^#   make' $(MAKEFILE_LIST) | sed 's/^#   //'

setup:
	npm ci
	docker compose up -d --wait db mail
	cp -n .env.example .env || true
	npm run db:migrate
	npm run db:seed
	python3 -m venv .venv
	$(PY) -m pip install --quiet -r security-runner/requirements.lock.txt
	$(PY) -m pip install --quiet -r security-runner/fuzz-requirements.txt
	npx playwright install chromium
	@echo
	@echo "Ready. 'make dev', then open http://localhost:3000"

dev:
	npm run dev

verify:
	npm run lint
	npm run typecheck
	npm run build
	npm run docs:check
	npm test
	npm run test:e2e

# Requires the application to be running (make dev in another terminal).
security:
	npm run semgrep:verify
	npm run security:run
	npm run security:fuzz
	npm run sbom
	$(PY) -m pytest security-runner -q

# Starts the intentionally vulnerable lab. Never expose this beyond loopback.
lab:
	docker compose --profile lab up -d --wait lab-db
	@echo "Run 'npm run lab' in another terminal, then 'npm run lab:demo'."

reset:
	npm run db:reset -- --confirm-local-reset

clean:
	docker compose --profile lab stop
