# Security policy

## What this project is

SecureWallet is a **local learning and assessment project**. It handles fake INR, runs on a developer machine, and is not a payment service. It is not deployed publicly and holds no real user data.

It ships with a **deliberately vulnerable lab** under `apps/api/src/lab/`. Everything in that directory is an intentional teaching fixture, documented as SW-01 through SW-08 in [docs/FINDINGS.md](docs/FINDINGS.md). Reports about the lab are not vulnerability reports.

**Never deploy the lab publicly.** It has no opt-out switch for its flaws because it exists to have them.

## Scope

| In scope                                                                  | Out of scope                                                                                                       |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| The secure application: `apps/api/src` (excluding `lab/`), `apps/web/src` | Anything under `apps/api/src/lab/` — intentional by design                                                         |
| The security tooling: `semgrep/`, `security-runner/`, `scripts/`          | Documented limitations in README and ARCHITECTURE                                                                  |
| The CI workflows under `.github/`                                         | Local demo credentials in `.env.example` — local-only by design                                                    |
| Documentation that materially misstates a control                         | Missing production concerns already recorded as not implemented: MFA, TLS, retention jobs, shared rate-limit store |

A finding that the application runs over plain HTTP locally, or that the demo database uses a superuser, is already documented. So is the absence of MFA. Those are stated limitations rather than undiscovered issues.

## Reporting

Open a **GitHub security advisory** on the repository, or a regular issue if the finding is in the documentation rather than the code.

Please include:

- which file and function, or which request
- the observed behaviour and the expected behaviour
- a minimal reproduction — the exact request, or a failing test

If you would rather not open anything public, say so in an issue without the details and a private channel can be arranged.

Since this is a personal learning project, expect a response in days rather than hours. There is no bounty.

## What happens to a report

1. **Triage** — confirmed as reproducible, scoped, and assigned a severity using CVSS v3.1 plus the qualitative rating explained in [docs/FINDINGS.md](docs/FINDINGS.md).
2. **Fix** — with a regression test that fails without the fix. A fix without a test is not finished.
3. **Detect** — where the class of bug can be expressed as a pattern, a rule is added to `semgrep/rules/` and `npm run semgrep:verify` proves it catches the case.
4. **Record** — added to `docs/FINDINGS.md` with root cause, impact and retest, including what the original reasoning got wrong.

SW-09, SW-10 and SW-11 in that document were found by this process applied to the project's own code, and are written up the same way as the planted ones.

## Verifying a checkout

```
npm run lint && npm run typecheck && npm run build
npm test
npm run test:e2e
npm run semgrep:verify
npm run security:run
npm run security:fuzz
```

`npm run security:lab` is **expected to exit 1**. It runs the authorization rules against the intentionally vulnerable lab, and three assertions are meant to fail. A passing result there would mean the lab had stopped demonstrating anything.
