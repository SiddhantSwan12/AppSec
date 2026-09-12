# SecureWallet — Digital Wallet AppSec Assessment Lab

A local digital wallet built to learn application security, where money movement has invariants a test can check: no balance goes negative, no transfer is ever half-applied, and a retried request never pays twice. Alongside it is an isolated, opt-in lab with eight deliberately introduced flaws, used to practise the full loop — reproduce, explain the impact, remediate, and prove the fix holds.

All funds are fake INR. This is not a payment service or a guarantee of security.

Three further findings — **SW-09, SW-10 and SW-11** — were not planted. They were found during self-review of code believed to be finished, and are written up in [findings](docs/FINDINGS.md) with the same rigour as the planted eight, including what the original reasoning got wrong.

|                                     |                                                             |
| ----------------------------------- | ----------------------------------------------------------- |
| Money invariant                     | [`apps/api/src/transfers.ts`](apps/api/src/transfers.ts)    |
| Findings and severity register      | [docs/FINDINGS.md](docs/FINDINGS.md)                        |
| ASVS 4.0.3 L1 self-assessment       | [docs/ASVS.md](docs/ASVS.md) — 48 met, 5 partial, 2 not met |
| Detection rules and runbook         | [docs/DETECTION-RUNBOOK.md](docs/DETECTION-RUNBOOK.md)      |
| Threat model (STRIDE + abuse cases) | [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)                |
| Supply chain                        | [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md)                |
| Reporting a vulnerability           | [SECURITY.md](SECURITY.md)                                  |

## Start here

Read [the learning guide](docs/LEARNING-GUIDE.md) while tracing the code. It explains sessions, authorization, transfer atomicity, locks, idempotency, findings, and interview questions. [Progress and verification](docs/PROGRESS.md) distinguishes actual results from limitations.

### Prerequisites

- Node.js 24 LTS and npm.
- Docker Desktop running Linux containers.
- Python 3.12+ for the regression runner.

The commands below run in PowerShell on Windows. **On macOS or Linux use the `Makefile` instead** — `make setup`, then `make dev`, `make verify` and `make security`; it runs the same steps with `npm` and `.venv/bin/`. `npm.cmd` avoids PowerShell execution-policy issues with npm's `.ps1` shim. Ports: web 3000, secure API 4000, secure PostgreSQL 54329, Mailpit 8025/1025; opt-in lab 4001 and lab PostgreSQL 54330.

```powershell
Copy-Item .env.example .env   # First setup only; do not overwrite an existing .env
npm.cmd ci
docker compose up -d --wait db mail
npm.cmd run db:migrate
npm.cmd run db:seed
npm.cmd run dev
```

Open [the wallet](http://localhost:3000) using **localhost**, matching `APP_ORIGIN`. The API proxies through the same origin. The `.env` file is ignored by Git. Example passwords and database credentials are public, local-only demonstration values, not real secrets.

| Account | Email              | Starting funds |
| ------- | ------------------ | -------------- |
| Alice   | alice@example.test | ₹1,000         |
| Bob     | bob@example.test   | ₹1,000         |
| Admin   | admin@example.test | ₹0             |

The password is `DEMO_PASSWORD` in `.env`; the example is `Demo-wallet-only-2026!`. Public registrations always receive the user role and a zero-balance wallet. Seed credits have ledger entries. Rerunning seed does not refill balances or change existing passwords.

Bob's recipient account ID: `22222222-2222-4222-8222-222222222222`. Alice's: `11111111-1111-4111-8111-111111111111`. Account IDs appear on the dashboard. Use Mailpit at [localhost:8025](http://localhost:8025) to inspect local password-reset emails. No external email provider is configured.

### Continuous integration

Three workflows run on every push and pull request, and weekly on a schedule:

- **`ci.yml`** — lint, typecheck, build, OpenAPI validation, 36 API tests, 12 browser tests, the Python unit tests and the configured authorization run, against real PostgreSQL and Mailpit service containers.
- **`security.yml`** — the project's own Semgrep rules (gating), community rulesets (reporting), gitleaks over full history, `npm audit` and OSV-Scanner, Trivy on both container images, a CycloneDX SBOM, plus schema-driven fuzzing and a ZAP baseline sweep against a running instance.
- **`codeql.yml`** — CodeQL `security-extended` for TypeScript and Python.

Jobs declare least-privilege `permissions:` and installs use `--ignore-scripts`. Actions are currently referenced by tag rather than commit SHA; [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) explains why and how to close it.

### Test the secure application

```powershell
npm.cmd run lint
npm.cmd run typecheck
npm.cmd run build
npm.cmd test
npm.cmd exec playwright install chromium
npm.cmd run test:e2e
```

`npm test` migrates and resets **only** `securewallet_test`, guarded by the database name. PostgreSQL and Mailpit must be running. Browser tests use the secure demo database, create throwaway accounts/tickets, send small fake transfers, and test local reset emails. They run desktop Chromium and a mobile Chromium viewport. This is not Safari/WebKit coverage. Browser credential traces are disabled. Screenshots contain fake dashboard data only.

If the test DB is missing because your Docker volume predates the init script:

```powershell
docker compose exec db createdb -U wallet securewallet_test
```

Run browser checks against the dev server; do not build and browse the same `.next` output concurrently. `test:e2e` starts dev if necessary or reuses it. Build verifies compilation; it does not deploy the application.

### Security tooling

```powershell
npm.cmd run semgrep:verify   # custom rules: catch every lab flaw, stay silent on the secure app
npm.cmd run security:fuzz    # schema-driven fuzzing from docs/openapi.json (needs dev running)
npm.cmd run sbom             # CycloneDX SBOM of the runtime dependency tree
```

`semgrep:verify` uses Semgrep from `PATH`, or the `semgrep/semgrep` container when it is absent — the normal path on Windows, where Semgrep has no native build. It asserts both directions: every finding-mapped rule fires on the intentionally vulnerable lab, and no rule fires on the secure application. A rule that stops matching is a failure, because a rule nobody tests is decoration.

`security:fuzz` generates requests from the OpenAPI document and asserts properties that must hold everywhere — never a 500, never an undeclared status, never a response that violates its own schema. It found SW-11 on its first run. Credential-mutating and throttled `/auth/*` routes are excluded deliberately; `scripts/fuzz.ts` documents which checks are disabled and why.

### Python authorization runner

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r security-runner/requirements.lock.txt
.\.venv\Scripts\python.exe -m pytest security-runner -q
npm.cmd run security:run
```

Keep `npm run dev` running in another terminal. The npm wrapper loads the demo password from `.env` without printing it. View [the generated secure report](docs/evidence/secure/authorization.html). The runner authenticates Alice, Bob, admin, and uses an anonymous client. It checks configured ownership/content expectations and redacts by whitelisting output fields, not by copying raw responses.

Exit codes: **0** all assertions passed; **1** security assertion failed; **2** setup/connection problem. Configuration defaults to loopback and disables redirects. A nonlocal authorized target requires explicit configuration. This is configured regression testing, not a universal vulnerability scanner.

### Start the intentionally vulnerable lab

```powershell
docker compose --profile lab up -d --wait lab-db
npm.cmd run lab
```

In another terminal:

```powershell
npm.cmd run lab:demo
npm.cmd run lab:reset
npm.cmd run security:lab
```

The lab uses [127.0.0.1:4001](http://127.0.0.1:4001), separate cookies and a separate database. `lab:demo` resets its fixtures and executes all eight demonstrations, including actual browser execution of a harmless stored-XSS marker. [Lab evidence](docs/evidence/lab-demonstrations.html) records observed results. `lab:reset` restores normal seeded roles before the authorization run. `security:lab` **intentionally exits 1** with three failed authorization assertions, recorded in [the lab report](docs/evidence/lab/authorization.html).

Never deploy this lab publicly. There is no switch in the secure app that disables its security. Lab fixtures intentionally use a smaller schema to expose the flaws; they are not a second full wallet product.

### Reset and stop

Reset **all secure local demo records**, including newly registered users, tickets, sessions, transfers and balances, then reseed:

```powershell
npm.cmd run db:reset -- --confirm-local-reset
```

This is an explicit destructive local-data operation. It requires the local `securewallet` database name. `npm run lab:reset` separately resets only lab data. Do not reset during another test run. Stop `dev` and `lab` with Ctrl+C in their terminals, then:

```powershell
docker compose --profile lab stop
```

`stop` preserves database volumes. No recursive file deletion or volume deletion is required for normal setup/reset.

## What is implemented

- Registration, login/logout, opaque sessions, password change and single-use expiring email reset.
- Backend role/ownership enforcement, CSRF/Origin checks, auth throttling, allowlisted inputs.
- Wallets, exact paise amounts, transfer confirmation, atomic debit/credit ledger, history/search/pagination.
- Concurrent overspending prevention and sender-scoped idempotency with mismatch handling.
- Plain-text support conversations, admin replies/status, paginated user/transfer/ticket/audit views.
- Eight isolated lab scenarios, repeatable demonstrations, JSON/HTML evidence, and the Python authorization runner.
- API integration and browser tests, architecture, threat model, authorization matrix, OpenAPI and interview guidance.
- Five detection rules over the audit trail, surfaced to administrators, with a response runbook per rule.
- Twelve custom Semgrep rules, verified against the lab as a labelled corpus, plus schema-driven API fuzzing.
- Three CI workflows covering SAST, SCA, secret scanning, container scanning, SBOM, CodeQL and DAST.

## Files to inspect first

1. `docs/LEARNING-GUIDE.md` — learn in a deliberate order.
2. `apps/api/src/auth.ts` and `security.ts` — identity, cookies, tokens and CSRF.
3. `apps/api/src/transfers.ts` and `db.ts` — the core money invariant.
4. `apps/api/tests/security.test.ts` — executable security expectations.
5. `apps/api/src/lab/server.ts` and `scripts/lab-demo.ts` — controlled flaw and evidence pairs.
6. `security-runner/runner.py` — configured authorization assessment.
7. `semgrep/rules/securewallet.yml` and `scripts/semgrep-verify.mjs` — each finding as a rule, and the proof the rules work.
8. `apps/api/src/detections.ts` — the audit trail read back as detection rules.

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md), [authorization matrix](docs/AUTHORIZATION.md), [ASVS coverage](docs/ASVS.md), [detection runbook](docs/DETECTION-RUNBOOK.md), [supply chain](docs/SUPPLY-CHAIN.md), [OpenAPI](docs/openapi.json), [findings and retests](docs/FINDINGS.md), [five-minute demo](docs/INTERVIEW-DEMO.md) and the [recorded walkthrough script](docs/DEMO-SCRIPT.md). Regenerate OpenAPI with `node scripts/openapi.mjs` after updating its endpoint/schema definitions.

## Limitations

Single-process local deployment; process-local throttling; demo DB superuser; no real payment integration, MFA, fraud engine, operational monitoring, retention jobs or public production deployment. Detection rules are evaluated on request with no alerting, and their thresholds are reasoned rather than measured against real traffic. GitHub Actions are referenced by tag rather than commit SHA. The full residual risk register is in [the threat model](docs/THREAT-MODEL.md). Reset email timing is not normalized. Browser idempotency recovery lasts while the confirmation remains open, not across tab loss. Audit events cover selected security-sensitive actions, not every request. Tests cover defined cases, not every attack, browser, or OWASP category. See the architecture document for the consequences and production considerations.
