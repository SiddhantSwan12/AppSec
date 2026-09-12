# Threat model

Scope: a local educational wallet with fake INR, a browser, one API instance, PostgreSQL and a local email catcher.

**Attacker capability assumed.** Register an ordinary account; alter any part of any HTTP request, including headers the application generates; guess known fixture identifiers; submit arbitrary text; and send concurrent or repeated requests. Host compromise and database-administrator compromise are outside the application's control boundary — an attacker with either already has everything the application protects.

**Assets.** Credentials and sessions; private tickets and transactions; wallet and ledger integrity; role assignments; reset tokens; audit records.

**Trust boundaries.** Browser → API. API → PostgreSQL. API → local mail. Secure application → deliberately vulnerable lab. Browser input is untrusted even when the application's own form produced it. Object identifiers identify records; they do not authorise access to them.

## STRIDE by trust boundary

STRIDE is applied per boundary rather than per feature, because a boundary is where an assumption changes hands. The **Residual** column is the part that is not solved.

### Boundary 1 — Browser to API

| STRIDE                     | Threat                                               | Control                                                                                | Residual                                                                             |
| -------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| **S**poofing               | Guessing or replaying another user's session         | 256-bit opaque tokens, SHA-256 at rest, 8-hour expiry checked per request              | No device binding; a stolen cookie is a valid session until it expires               |
| **S**poofing               | Password guessing against a known account            | Argon2id, generic errors, source **and** account throttling (SW-09)                    | Counters are process-local; a second API instance doubles every limit                |
| **T**ampering              | Forging the sender, amount or role in a request      | Sender derived from the session; strict writable allowlists; integer paise with bounds | None known at this boundary                                                          |
| **T**ampering              | Cross-site request forgery                           | Exact Origin match plus a host-only HttpOnly double-submit token; SameSite=Strict      | An XSS flaw would defeat this, which is why SW-10 matters                            |
| **T**ampering              | Forged `X-Forwarded-For` to choose a throttle bucket | `trust proxy` limited to `loopback`; production refuses `TRUST_PROXY=true`             | Anything that reaches the API directly can still forge it. The API binds to loopback |
| **R**epudiation            | Denying a transfer or an administrative action       | Audit events for authentication, transfers and ticket status changes                   | Audit rows are append-only by convention only; the demo DB is a superuser            |
| **I**nformation disclosure | Reading another account's tickets or transactions    | SQL ownership predicates; 404 rather than 403 for private records                      | None known; DET-05 reports attempts                                                  |
| **I**nformation disclosure | Account enumeration via login or reset responses     | Generic responses; a dummy hash equalises the work on unknown accounts                 | Response **timing** is not normalised, and reset email delivery is not constant-time |
| **I**nformation disclosure | Stored payload executing in a viewer's session       | React text rendering; CSP with a per-response nonce (SW-10)                            | `strict-dynamic` permits non-parser-inserted scripts by design                       |
| **D**enial of service      | Exhausting authentication for every user at once     | Per-source and per-account buckets; successful logins skip the account bucket (SW-09)  | In-memory store; no edge rate limiting                                               |
| **D**enial of service      | Oversized or malformed bodies                        | 16 KB JSON limit; typed schemas; control characters rejected (SW-11)                   | No per-account request quota outside authentication                                  |
| **E**levation of privilege | Assigning oneself the admin role                     | Role absent from every writable schema; admin created only by seed code                | None known; `sw-writable-protected-attribute` guards regression                      |
| **E**levation of privilege | Reaching an admin function as a normal user          | `adminOnly` at the router **and** on each route                                        | None known                                                                           |

### Boundary 2 — API to PostgreSQL

| STRIDE                     | Threat                                      | Control                                                                              | Residual                                                   |
| -------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| **T**ampering              | Input altering query structure              | Parameterised values everywhere; admin statements are complete literals              | None known; `sw-sql-string-interpolation` fails the build  |
| **T**ampering              | Partial money movement on failure           | One connection, one transaction; rollback covers debit, credit, ledger and key claim | None known                                                 |
| **T**ampering              | Concurrent transfers overspending a balance | Both wallet rows locked in ascending ID order; balance read under the lock           | None known                                                 |
| **T**ampering              | A retry becoming a second payment           | Sender-scoped unique key plus payload fingerprint, claimed in the same transaction   | Recovery does not survive the browser tab closing          |
| **I**nformation disclosure | Search input widening its own result set    | Ownership predicate is structural; LIKE metacharacters escaped                       | None known                                                 |
| **D**enial of service      | Input the storage layer cannot represent    | Control characters rejected before the driver sees them (SW-11)                      | None known                                                 |
| **E**levation of privilege | Application role exceeding what it needs    | **Not controlled.** The demo connects as a superuser for migration convenience       | A real deployment needs a least-privilege application role |

### Boundary 3 — API to local mail

| STRIDE                     | Threat                                     | Control                                                                                         | Residual                                      |
| -------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------- | --------------------------------------------- |
| **I**nformation disclosure | Reset token captured in transit or in logs | Token travels in a URL **fragment**, which is never sent to a server or written to request logs | Plain SMTP on loopback; no transport security |
| **S**poofing               | Reset link requested for someone else      | Single-use token, 20-minute expiry, consumed inside a transaction                               | Anyone who reads the mailbox owns the account |

### Boundary 4 — Secure application to the vulnerable lab

| STRIDE                     | Threat                                          | Control                                                                                                     | Residual                                                            |
| -------------------------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **E**levation of privilege | Lab flaws reachable from the secure application | Separate process, database, credentials, port, cookie names; the secure entry point never imports `src/lab` | None known within the documented setup                              |
| **T**ampering              | A lab session accepted by the secure API        | Different cookie names and different hosts (`localhost` vs `127.0.0.1`)                                     | Browser cookie isolation depends on that host split being respected |
| **I**nformation disclosure | The lab reached from outside the machine        | Bound to loopback; behind an opt-in Docker profile                                                          | **No technical control against deploying it.** Documentation only   |

## Abuse cases

Threat tables enumerate what could be done to a component. These describe what an attacker is actually trying to achieve, which is a different question and produces different controls — DET-04 exists because of A2 and would not have been written from the tables above.

**A1 — "I bought a credential dump and want to find which accounts work here."**
Spread a few guesses over thousands of accounts so no account trips its own limit. Defeats DET-01 by design. Caught by DET-02, which groups by source and counts distinct accounts. Defeated in turn by rotating addresses — documented in the runbook rather than claimed solved.

**A2 — "I have one working credential and want the money out before anyone notices."**
Sign in legitimately and issue many valid transfers. Every request is authorised, correctly validated and correctly recorded. No per-request control can see this; only the pattern is visible, which is DET-04.

**A3 — "I want to read other customers' support tickets."**
Sign up legitimately, then iterate ticket identifiers. Blocked structurally by the ownership predicate. The attempt is visible through DET-05, so a regression in that predicate would show as someone finding it rather than as silence.

**A4 — "I want this wallet unusable during a promotion."**
Not theft — denial. Before SW-09 this cost roughly 30 requests: exhaust the single shared authentication bucket and nobody can sign in, change a password, or reset one. The most damaging thing an unauthenticated attacker could do to this application required no exploit and no account.

**A5 — "I want to act as an administrator."**
Try the role as a registration field, as a profile field, and as an admin route with only a session. All three are the planted findings SW-05, SW-02 and SW-01, which is what makes them worth planting.

**A6 — "I want to know whether this person banks here."**
Not access — inference. Submit an address to login and to password reset and compare the responses. Bodies are identical and a dummy hash equalises the work on the login path. **Timing is not normalised**, and reset email delivery is not constant-time, so this is partially open and stated as such.

## Residual risk register

| Risk                                               | Why it is accepted here                                           | What production needs                               |
| -------------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------- |
| No TLS                                             | Local HTTP by design; production boot refuses to start without it | Terminate TLS, `__Host-` cookies, HSTS              |
| Process-local rate limiting                        | One API instance                                                  | Shared store; edge rate limiting                    |
| Demo database superuser                            | Migration convenience on a throwaway database                     | Least-privilege application role                    |
| No MFA                                             | Out of scope for this project                                     | TOTP or WebAuthn on login and on high-value actions |
| Response timing not normalised                     | Partial enumeration resistance is honest, full is hard            | Constant-time paths, queued mail delivery           |
| No retention or cleanup jobs                       | Nothing here is long-lived                                        | Session, token, audit and idempotency retention     |
| Idempotency keys persist indefinitely              | Small demo dataset                                                | Expiry aligned to the retry window                  |
| Audit rows are not tamper-evident                  | Single-operator local project                                     | Append-only grants; ship events off-host            |
| Source addresses stored without a retention period | Needed for DET-02; local fake data                                | Retention policy and deletion job                   |
| Detection thresholds are reasoned, not measured    | No production traffic to baseline against                         | Tune against real traffic before alerting on them   |
| Actions referenced by tag rather than commit SHA   | SHAs must be resolved against upstream at pinning time            | Pin with `pinact`; Dependabot maintains them        |
| No independent penetration test                    | Personal project                                                  | External review                                     |

Positive test results prove the specified cases held. They do not prove the absence of anything.
