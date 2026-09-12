# Implementation progress

## Milestones

1. **Implemented:** npm monorepo, PostgreSQL migration/seed, registration/login/logout, sessions, password change/reset and frontend shell.
2. **Implemented:** wallet balances, integer-paise transfers, ledger, history/search/pagination, deterministic locking and sender-scoped idempotency.
3. **Implemented:** support conversations, plain-text comments, admin replies/status, read-only admin lists and backend authorization.
4. **Implemented:** separate loopback lab, separate PostgreSQL database, all eight vulnerable fixtures and reproducible demonstrations.
5. **Implemented:** Python configured authorization runner, JSON/HTML reports, explicit pass/failure/setup exit codes and reporting tests.
6. **Implemented:** README, architecture, threat model, authorization matrix, OpenAPI, findings/remediation/retests, learning guide, five-minute interview demo and frontend verification.
7. **Implemented:** self-review of the secure application producing SW-09, SW-10 and SW-11, each with root cause, CVSS vector, remediation and regression tests.
8. **Implemented:** twelve custom Semgrep rules with a two-way verification script, three CI workflows (CI, security, CodeQL), Dependabot, CycloneDX SBOM and supply-chain documentation.
9. **Implemented:** five detection rules over the audit trail, an admin detections view, a response runbook, and schema-driven API fuzzing.
10. **Implemented:** ASVS 4.0.3 L1 self-assessment, STRIDE threat model with abuse cases, security policy and disclosure scope, and a recorded-walkthrough script.

## Actual verification

| Check                                     | Result                                                                     | Evidence                                                 |
| ----------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------- |
| Database migrations and seed              | Passed on local PostgreSQL 18                                              | Running secure database and seeded accounts              |
| `npm run typecheck`                       | Passed                                                                     | API and frontend TypeScript                              |
| `npm run lint`                            | Passed, zero warnings                                                      | ESLint                                                   |
| `npm run build`                           | Passed                                                                     | API compilation and Next.js optimized build              |
| `npm test`                                | **36 passed**                                                              | `evidence/api-tests.json`                                |
| `npm run test:e2e`                        | **12 passed** (2 are expected-failure markers)                             | `evidence/browser-tests.json`                            |
| `npm run semgrep:verify`                  | **9/9 rules detected their finding, 0 findings on the secure app**, exit 0 | `evidence/semgrep-verification.json`                     |
| `npm run security:fuzz`                   | **1113 generated cases, 0 failures**, 3 informational warnings             | `evidence/fuzz-junit.xml`                                |
| `npm run sbom`                            | 81 runtime components, CycloneDX 1.5                                       | `evidence/sbom.cdx.json`                                 |
| Python pytest                             | **7 passed**                                                               | `evidence/python-tests.xml`                              |
| `npm run security:run`                    | **8/8 rules passed**, exit 0                                               | `evidence/secure/authorization.json` and `.html`         |
| `npm run lab:demo`                        | **8/8 expected insecure outcomes observed**, exit 0                        | `evidence/lab-demonstrations.json` and `.html`           |
| `npm run security:lab`                    | **3 expected failures, 5 passes**, exit 1                                  | `evidence/lab/authorization.json` and `.html`            |
| OpenAPI validation                        | Passed using `@apidevtools/swagger-parser`                                 | `docs/openapi.json`                                      |
| Desktop/mobile visual review              | Inspected screenshots; no horizontal overflow in browser flow              | `evidence/dashboard-desktop.png`, `dashboard-mobile.png` |
| Design detector                           | No findings                                                                | Inspected interface source and CSS                       |
| npm dependency audit during final install | 0 reported vulnerabilities                                                 | Installation output; not a guarantee of security         |

Browser checks cover registration, local email reset and subsequent login, a real transfer, history, support creation, literal rendering of an XSS payload, logout, and recovery from a simulated wallet API failure without displaying a false zero balance. Mobile coverage uses Chromium emulation, not Safari.

Concurrency tests use real PostgreSQL locks as a synchronization barrier. The rollback test deliberately raises a database error; the expected server log for that test is not an unexpected suite failure. The lab race uses a two-participant barrier and observes both transfers succeeding with a negative balance.

## Self-review findings

Three defects were found in the secure application after it was believed complete. Full write-ups are in `docs/FINDINGS.md`.

- **SW-09 (High)** — authentication throttling keyed on `req.ip` with `trust proxy` never set, so every request bucketed as `127.0.0.1` and the 30-per-15-minute limit was one global budget for the whole deployment. Roughly 30 requests from an unauthenticated attacker denied sign-in, password change and password reset to every user. Fixed with `trust proxy`, a second account-keyed limiter, and a production guard against `TRUST_PROXY=true`.
- **SW-10 (Medium)** — no Content-Security-Policy on the wallet interface, while the intentionally vulnerable lab had one. No independent CVSS: it is a missing mitigating control rather than an exploitable weakness. Fixed with a per-response nonce policy in `apps/web/src/proxy.ts`.
- **SW-11 (Low)** — a NUL byte in any free-text field returned 500, because PostgreSQL cannot store code point 0 in a `text` value. Found by the schema-driven fuzzer on its first run against the secure application. Fixed with shared control-character validation, and the OpenAPI document was updated to match.

SW-09 also exposed that **failed sign-ins were never recorded at all**: the login handler threw on bad credentials and the throw rolled back the audit row with the transaction. The detection rules depend on that record, so this was fixed alongside it.

## Known issues

- `tests/browser/hydration.spec.ts`, `hydration survives extension-body` is marked `test.fail()`. With Grammarly-style attributes present on `<body>` before React loads, React 19 does not hydrate and a Link navigation falls back to a full document load. This is pre-existing and unrelated to the security work; the previous version of the test asserted only the absence of console warnings, which passed without detecting it. Marked failing so the suite flags the day it is fixed rather than hiding it.
- GitHub Actions are referenced by tag rather than commit SHA. See `docs/SUPPLY-CHAIN.md` for why and the command to close it.

## Issues found and resolved during implementation

- Docker engine initially stopped: started Docker Desktop and provisioned services.
- Frontend TypeScript initially targeted ES2017: changed to ES2022 for exact BigInt currency parsing.
- Five initial transfer tests failed because unary minus on an untyped PostgreSQL parameter was ambiguous: explicitly cast ledger amounts to bigint, then retested.
- Root lab script needed ESM for top-level await: set the root package type to module.
- Python cache creation hit a local Windows/OneDrive permission warning: disabled pytest's optional cache provider; final run passed without that warning.
- Error-state browser test initially matched Next.js's route announcer as well as the application alert: scoped the test to the actual notice and reran successfully.
- Removed the development indicator from the interface and prevented failed wallet loads from rendering default balance data.

## Operating state and limitations

The secure dev server and lab were left running for local review. Docker data is persistent. Browser checks intentionally created test accounts, support tickets, reset emails and small fake transfers in the demo database. Starting balances therefore differ from a fresh seed. Use the documented explicit reset command only if you want to discard those local records.

No public deployment or production security certification was attempted. Single-process rate limiting, demo DB privileges, missing MFA/fraud/retention operations, reset timing, and tab-loss idempotency recovery are documented in ARCHITECTURE.md. The secure rollback and concurrency behavior was tested; full production failure recovery and cross-browser compatibility were not.

Git was initialized and dependency lockfiles are present. **No commit has been created**, because no Git author name/email is configured in this workspace and no identity was invented. The repository therefore has no history and nothing is published. Configuring `user.name` and `user.email` and making an initial commit is the outstanding prerequisite for the CI workflows to run at all. Next.js generated `apps/web/AGENTS.md` and `CLAUDE.md`; its bundled guidance was read during verification.

## Resume / learn

Use README for exact startup, seed/reset, test and stop commands. Begin with LEARNING-GUIDE.md, then follow `auth.ts`, `security.ts`, `transfers.ts`, and their tests. No implementation milestone remains open within the documented local scope; future extensions should start from the stated limitations rather than claiming untested production readiness.
