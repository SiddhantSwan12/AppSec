# OWASP ASVS coverage

Mapped against **OWASP Application Security Verification Standard 4.0.3, Level 1**, with selected Level 2 requirements where they were implemented anyway.

This is a self-assessment, not a certification, and it covers only the chapters relevant to a session-authenticated web application with a single relational store. Chapters with no applicable surface — V12 File Upload, V13 Web Services beyond REST, V14.6 mobile — are omitted rather than marked as passing, because a requirement that cannot fail is not evidence of anything.

Every **Met** row names the test that proves it. A requirement claimed without a test that fails when the control is removed is an assertion, not verification.

## Summary

| Chapter                     | Applicable | Met    | Partial | Not met |
| --------------------------- | ---------- | ------ | ------- | ------- |
| V1 Architecture             | 4          | 4      | 0       | 0       |
| V2 Authentication           | 9          | 7      | 1       | 1       |
| V3 Session Management       | 7          | 7      | 0       | 0       |
| V4 Access Control           | 5          | 5      | 0       | 0       |
| V5 Validation & Encoding    | 8          | 8      | 0       | 0       |
| V7 Error Handling & Logging | 6          | 5      | 1       | 0       |
| V8 Data Protection          | 4          | 3      | 1       | 0       |
| V9 Communications           | 2          | 0      | 1       | 1       |
| V11 Business Logic          | 4          | 4      | 0       | 0       |
| V14 Configuration           | 6          | 5      | 1       | 0       |
| **Total**                   | **55**     | **48** | **5**   | **2**   |

The two **Not met** rows are both deliberate and both about deployment rather than code: this project runs over local HTTP and has no MFA. Neither is claimed as done anywhere else in the documentation.

## V1 Architecture, Design and Threat Modelling

| Req    | Requirement                                     | Status | Evidence                                                                                                                       |
| ------ | ----------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------ |
| 1.1.2  | Threat modelling for every design change        | Met    | `docs/THREAT-MODEL.md`, STRIDE per trust boundary, with abuse cases                                                            |
| 1.1.5  | Trust boundaries defined, data flows documented | Met    | `docs/ARCHITECTURE.md` flow diagram; boundary table in the threat model                                                        |
| 1.4.1  | Access control enforced at a trusted layer      | Met    | `apps/api/src/security.ts`; UI navigation hiding is presentation only, stated in AUTHORIZATION.md                              |
| 1.14.6 | Untrusted code isolated from production paths   | Met    | The vulnerable lab has a separate process, database, port and cookie namespace; the secure entry point never imports `src/lab` |

## V2 Authentication

| Req   | Requirement                                        | Status  | Evidence                                                                                                                     |
| ----- | -------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 2.1.1 | Passwords at least 12 characters                   | Met     | `password` schema in `auth.ts`; rejection covered by registration tests                                                      |
| 2.1.7 | Credentials checked against breach corpora         | Not met | No breach-corpus lookup. Deliberate: it needs an external service this local project does not have                           |
| 2.2.1 | Anti-automation on authentication                  | Met     | `throttle.ts`, source and account limiters; `SW-09 source and account throttling` tests                                      |
| 2.2.2 | No security questions or weak recovery             | Met     | Recovery is a single-use expiring emailed token only                                                                         |
| 2.4.1 | Passwords stored with an approved KDF              | Met     | Argon2id, 19 MiB / t=2 / p=1, `security.ts`; `sw-fast-hash-for-password` guards against regression                           |
| 2.5.4 | No default or shared accounts                      | Met     | Seeded demo accounts only, created by seed code; public registration cannot assign a role                                    |
| 2.5.6 | Recovery tokens random, short-lived, single use    | Met     | 256-bit token, SHA-256 at rest, 20 minutes, `used_at` consumed inside the transaction; reset tests                           |
| 2.5.7 | Recovery invalidates existing sessions             | Met     | `DELETE FROM sessions` on reset and on password change; revocation tests                                                     |
| 2.8.1 | Multi-factor authentication available              | Not met | No MFA. Stated as a limitation in README and ARCHITECTURE                                                                    |
| 2.2.3 | Notify users of suspicious authentication activity | Partial | Failed sign-ins are recorded and surfaced to administrators through DET-01 and DET-02, but the account owner is not notified |

## V3 Session Management

| Req   | Requirement                                        | Status | Evidence                                                                            |
| ----- | -------------------------------------------------- | ------ | ----------------------------------------------------------------------------------- |
| 3.2.1 | New session token generated on authentication      | Met    | A fresh 256-bit token per login; CSRF token rotated with it                         |
| 3.2.2 | Session tokens have at least 64 bits of entropy    | Met    | `randomBytes(32)`, 256 bits                                                         |
| 3.2.3 | Tokens stored securely, never in local storage     | Met    | HttpOnly cookie only; asserted by the cookie-flag test                              |
| 3.3.1 | Logout invalidates the session server-side         | Met    | Server-side row deletion, not just cookie clearing; logout test asserts reuse fails |
| 3.3.2 | Inactivity or absolute timeout enforced            | Met    | 8-hour absolute expiry checked in SQL on every request; expiry test                 |
| 3.4.1 | Cookie-based tokens use Secure                     | Met    | Driven by `COOKIE_SECURE`; production boot fails without HTTPS plus Secure          |
| 3.4.2 | Cookie-based tokens use HttpOnly                   | Met    | `cookieOptions`; asserted in tests and guarded by `sw-session-cookie-missing-flags` |
| 3.4.3 | SameSite set to limit cross-site sending           | Met    | `SameSite=Strict` on session and CSRF cookies                                       |
| 3.5.3 | Stateless tokens not used where revocation matters | Met    | Opaque server-side sessions, deliberately not JWTs, so revocation is immediate      |

## V4 Access Control

| Req   | Requirement                                                | Status | Evidence                                                                                                                 |
| ----- | ---------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------ |
| 4.1.1 | Access controls enforced server-side                       | Met    | SQL ownership predicates plus `adminOnly`; the Python runner drives four real actors                                     |
| 4.1.2 | Attributes used for access decisions are not user-settable | Met    | Role never appears in a writable schema; `sw-writable-protected-attribute` guards it                                     |
| 4.1.3 | Principle of least privilege per function                  | Met    | Authorization matrix in `docs/AUTHORIZATION.md`; admin lists are read-only, with no balance-edit endpoint at all         |
| 4.2.1 | Protection against direct object reference tampering       | Met    | Every per-user lookup carries an ownership predicate; `sw-record-lookup-without-owner-predicate` is the regression guard |
| 4.3.1 | Administrative interfaces use appropriate authorisation    | Met    | Router-level `adminOnly` plus a per-route guard; every admin list covered by tests                                       |

## V5 Validation, Sanitisation and Encoding

| Req    | Requirement                                       | Status | Evidence                                                                                      |
| ------ | ------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------- |
| 5.1.1  | No mass assignment of protected fields            | Met    | Zod `.strict()` on every write schema; protected-field tests                                  |
| 5.1.3  | All input validated positively (allowlist)        | Met    | Typed schemas per endpoint, not sanitisation of denied values                                 |
| 5.1.4  | Structured data strongly typed and range-checked  | Met    | Integer paise, positive, bounded; boundary tests for zero, negative, fractional and excessive |
| 5.2.1  | Untrusted HTML sanitised or escaped               | Met    | React text rendering; browser test asserts an `<img onerror>` payload renders literally       |
| 5.2.3  | Untrusted data not interpreted as executable      | Met    | CSP with a per-response nonce; `headers.spec.ts` asserts the inline handler does not fire     |
| 5.3.4  | Parameterised queries throughout                  | Met    | Every statement bound; `sw-sql-string-interpolation` fails the build otherwise                |
| 5.3.10 | Protection against injection into the query layer | Met    | LIKE metacharacters escaped so search input cannot alter matching behaviour                   |
| 5.5.2  | Input restricted to characters the sink accepts   | Met    | `validation.ts` rejects control characters the storage layer cannot hold (SW-11)              |

## V7 Error Handling and Logging

| Req   | Requirement                                        | Status  | Evidence                                                                                                                                  |
| ----- | -------------------------------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| 7.1.1 | No sensitive data in logs                          | Met     | The error handler logs an error name only; the Python runner allowlists report fields                                                     |
| 7.1.2 | No credentials or payment details logged           | Met     | Reset tokens travel in a URL fragment specifically to stay out of request logs                                                            |
| 7.2.1 | Authentication decisions logged                    | Met     | `auth.login`, `auth.login_failed`, `auth.logout` with source address                                                                      |
| 7.2.2 | Access control failures logged                     | Met     | `authz.denied` emitted from the error handler; DET-05 consumes it                                                                         |
| 7.4.1 | Generic messages to the user on unexpected failure | Met     | Single generic 500 body; enumeration-safe login and reset responses                                                                       |
| 7.3.1 | Logs protected from tampering and injection        | Partial | Audit rows are append-only by convention, not by grant. The demo database uses a superuser, so nothing prevents an operator deleting rows |

## V8 Data Protection

| Req   | Requirement                               | Status  | Evidence                                                                                                            |
| ----- | ----------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------- |
| 8.1.1 | Sensitive data not cached by the client   | Met     | `Cache-Control: no-store` on every `/api` response                                                                  |
| 8.2.1 | No sensitive data in URLs                 | Met     | Reset tokens use the fragment; identifiers in paths are not secrets                                                 |
| 8.3.4 | Sensitive data inventoried and classified | Met     | Asset list in `docs/THREAT-MODEL.md`                                                                                |
| 8.3.8 | Retention and deletion defined            | Partial | No retention job. Sessions expire but rows persist; idempotency keys persist indefinitely. Recorded as a limitation |

## V9 Communications

| Req   | Requirement                    | Status  | Evidence                                                                                                                                    |
| ----- | ------------------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 9.1.1 | TLS for all client connections | Not met | Local HTTP by design. Production boot refuses to start without an HTTPS origin and Secure cookies, so the control exists but is unexercised |
| 9.2.2 | TLS for outbound connections   | Partial | The local mail catcher is plain SMTP on loopback; no external provider is configured                                                        |

## V11 Business Logic

| Req    | Requirement                                       | Status | Evidence                                                                                                                        |
| ------ | ------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------- |
| 11.1.1 | Logic flows process in sequence, no skipped steps | Met    | Debit, credit, ledger and key claim commit in one transaction on one connection                                                 |
| 11.1.2 | Limits appropriate to the business enforced       | Met    | Per-transfer cap, wallet balance cap, insufficient-funds check under lock                                                       |
| 11.1.4 | Anti-automation on high-value flows               | Met    | Sender-scoped idempotency keys; DET-04 reports transfer velocity                                                                |
| 11.1.6 | No exploitable race conditions                    | Met    | Deterministic lock ordering; the concurrency test holds a lock until both requests are waiting and asserts exactly one succeeds |

## V14 Configuration

| Req    | Requirement                                   | Status  | Evidence                                                                                                                                                      |
| ------ | --------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 14.1.1 | Build and deploy are repeatable and automated | Met     | `.github/workflows/ci.yml`                                                                                                                                    |
| 14.2.1 | Dependencies kept current                     | Met     | Dependabot across npm, pip, Docker and Actions; `npm audit` and OSV-Scanner gate the build                                                                    |
| 14.2.4 | Integrity of third-party components verified  | Partial | Lockfiles pin transitively and installs run `--ignore-scripts`, but workflow Actions are referenced by tag rather than commit SHA. See `docs/SUPPLY-CHAIN.md` |
| 14.3.2 | Debug and diagnostic features disabled        | Met     | `x-powered-by` disabled; dev indicator off; generic error bodies                                                                                              |
| 14.4.1 | HTTP response headers set safely              | Met     | helmet on the API; CSP, nosniff, frame-deny, referrer and COOP/CORP on the web app; `headers.spec.ts`                                                         |
| 14.5.3 | CORS configured restrictively                 | Met     | No CORS at all. The interface is same-origin through a rewrite, and state-changing requests require an exact Origin match                                     |

## How to re-verify

```
npm run lint && npm run typecheck && npm run build
npm test            # 36 API and integration cases
npm run test:e2e    # 12 browser cases, desktop and mobile
npm run semgrep:verify
npm run security:run
npm run security:fuzz
```

`docs/PROGRESS.md` records the last observed result of each, and the CI workflows run all of them on every change.
