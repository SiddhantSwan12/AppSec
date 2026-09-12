# Security findings

Findings come from two different places, and the distinction matters when reading this document.

**SW-01 through SW-08 are controlled vulnerabilities introduced in the local lab**, not vulnerabilities discovered in a real company. The secure application is the remediation counterpart; the lab remains vulnerable so the demonstrations stay reproducible.

**SW-09, SW-10 and SW-11 were discovered during self-review of the secure implementation.** They are real defects that existed in code believed to be correct. SW-09 and SW-10 came from re-reading the authentication and response-header paths against the threat model rather than against a list of planted flaws; SW-11 came from the schema-driven fuzzer on its first run. They are recorded with the same structure as the planted findings, including what the original reasoning got wrong.

That distinction is the point of the exercise. Eight flaws planted on purpose show that a class of bug is understood. Three found in code that was believed finished show what a review actually produces.

Severity expresses risk in a comparable wallet holding real assets, not actual financial loss in this fake-funds lab.

## Severity register

CVSS v3.1 base vectors are given with the metric that drives the score. Base scores deliberately exclude temporal and environmental metrics; the qualitative severity column is the rating for **this** application, which is not always the same number, and the gap is explained per finding.

| ID    | Title                                      | CWE      | OWASP Top 10 2021    | CVSS v3.1 base                      | Score      | Rated  |
| ----- | ------------------------------------------ | -------- | -------------------- | ----------------------------------- | ---------- | ------ |
| SW-01 | Ticket readable by another user            | CWE-639  | A01 Access Control   | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 Medium | High   |
| SW-02 | Admin user list reachable by any account   | CWE-862  | A01 Access Control   | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 Medium | High   |
| SW-03 | Search input changes SQL structure         | CWE-89   | A03 Injection        | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 High   | High   |
| SW-04 | Stored comment executes in a viewer page   | CWE-79   | A03 Injection        | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N | 8.7 High   | High   |
| SW-05 | Profile update permits role escalation     | CWE-915  | A04 Insecure Design  | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 High   | High   |
| SW-06 | Negative amount reverses money flow        | CWE-20   | A04 Insecure Design  | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 6.5 Medium | High   |
| SW-07 | Concurrent requests overspend a balance    | CWE-362  | A04 Insecure Design  | AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N | 5.3 Medium | High   |
| SW-08 | Retried request processed twice            | CWE-837  | A04 Insecure Design  | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 6.5 Medium | High   |
| SW-09 | Authentication throttle shared by everyone | CWE-770  | A04 Insecure Design  | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | 7.5 High   | High   |
| SW-10 | No Content-Security-Policy on the web app  | CWE-1021 | A05 Misconfiguration | no independent score — see SW-10    | n/a        | Medium |
| SW-11 | NUL byte in support text returns 500       | CWE-20   | A04 Insecure Design  | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L | 4.3 Medium | Low    |

Where the computed score and the rating disagree, the rating wins for planning and the score is still reported. SW-06, SW-07 and SW-08 are the clearest cases: CVSS has no dimension for money, so an unauthorised debit scores as ordinary integrity loss. In a payment system an attacker-controlled balance change is the worst outcome the product has, which is why they are worked as High regardless of a 5.3 or 6.5 base. Reporting only the number, or only the adjective, would hide that judgement.

## Reproduce the evidence

Start the lab database and server as described in README, then run `npm run lab:demo`. This command checks the explicit lab health marker, resets **only** the guarded lab fixtures, authenticates Alice/Bob, runs all eight demonstrations, and writes `docs/evidence/lab-demonstrations.json` and `.html`. The script is also the exact executable request sequence for every finding. Inspect `scripts/lab-demo.ts` and `apps/api/src/lab/server.ts` together.

For manual replay, use a client cookie jar: GET `/api/v1/auth/csrf`, POST `/api/v1/auth/login` with a seeded account, then send the returned token in `X-CSRF-Token` and `Origin: http://127.0.0.1:4001` on writes. Do not print or save the cookie jar in evidence. All paths below are on `http://127.0.0.1:4001` unless explicitly marked secure.

## SW-01 — Another user can read Alice's ticket

**Rule:** a ticket is visible only to its owner or an administrator handling support. **Severity: High**, because another ordinary account can obtain private support content by supplying a known identifier. Mapping: [CWE-639](https://cwe.mitre.org/data/definitions/639.html).

**Vulnerable implementation:** the lab ticket query filters by `id` only. Reproduce as Bob: GET `/api/v1/tickets/44444444-4444-4444-8444-444444444444`. **Observed:** HTTP 200 with Alice's user ID and private ticket. Bob's own ID differs from the returned owner.

**Root cause:** record identification is mistaken for authorization. **Business impact:** disclosure of another customer's support information. **Remediation:** the secure query requires the ticket ID plus `(user_id = authenticated user OR authenticated role = admin)`.

**Retest/regression:** the secure API returns 404 to Bob, 200 with the expected owner to Alice/admin, and 401 to anonymous. Covered by the API access-matrix test and Python configured ticket rules. Actual secure and lab reports are in `docs/evidence/secure` and `docs/evidence/lab`.

## SW-02 — Ordinary users can list administrator-only accounts

**Rule:** only admins may list users. **Severity: High**, because a regular account reaches an administrative data function. Mapping: [CWE-862](https://cwe.mitre.org/data/definitions/862.html).

**Vulnerable implementation:** the lab requires a session but omits a role check. Reproduce as Bob before the mass-assignment demo: GET `/api/v1/admin/users`. **Observed:** HTTP 200 with three seeded account records while Bob's role is `user`.

**Root cause:** authentication alone guards an administrative route. **Business impact:** account enumeration and unauthorized administrative data access; no balance-edit capability is claimed. **Remediation:** the secure router applies `adminOnly` to the `/admin` prefix.

**Retest/regression:** secure ordinary users receive 403; anonymous receives 401; admins receive records without password hashes. Python detects both Alice and Bob failures in the lab, while secure rules pass. API tests cover every admin list and ticket status mutation.

## SW-03 — Search input changes SQL structure

**Rule:** transaction searches must treat input as data and preserve ownership filters. **Severity: High**, because authenticated input bypasses the private-record filter. Mapping: [CWE-89](https://cwe.mitre.org/data/definitions/89.html).

**Vulnerable implementation:** the lab interpolates `search` inside an SQL string. Reproduce as Alice: first GET `/api/v1/transactions`, then the same request with URL-encoded search `' OR true --`. **Observed:** zero normal results become one result belonging to the seeded Bob/admin fixture.

**Root cause:** user text becomes SQL syntax. **Business impact:** unauthorized transaction disclosure; the demo does not claim to prove every possible SQL injection impact. **Remediation:** the secure query uses `$1`, `$2`, `$3` parameters, with a separately fixed SQL structure.

**Retest/regression:** the secure injection-string search returns 200 with no matching rows. Tests also cover pagination and ownership. Lab evidence records the counts and exposed sender ID without credentials.

## SW-04 — Stored comment executes in the viewer's page

**Rule:** support comments are plain text. **Severity: High**, because attacker-authored persistent content executes in a viewer's origin. Mapping: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).

**Vulnerable implementation:** lab `/comments` directly inserts stored bodies into an HTML response. Reproduce: POST `/api/v1/comments` with body `<script>document.body.dataset.labXss='executed'</script>`, then visit `/comments` with that authenticated lab session. **Observed:** Playwright reads `data-lab-xss="executed"` from the body. The lab CSP prevents external resource loading; the demo changes only a local marker.

**Root cause:** untrusted text is rendered as executable markup. **Business impact:** an equivalent flaw could act in a viewer's authenticated context. HttpOnly alone does not make such execution harmless. **Remediation:** the secure React conversation renders `{c.body}` as text, with no HTML insertion.

**Retest/regression:** desktop/mobile browser tests store an `<img onerror=...>` payload in the secure support flow, assert its literal text, verify no image node was created, and check that no execution marker exists.

## SW-05 — Profile update permits role escalation

**Rule:** users may change only allowlisted profile attributes, never their own role. **Severity: High**, because the protected role is overwritten by ordinary user input. Mapping: [CWE-915](https://cwe.mitre.org/data/definitions/915.html).

**Vulnerable implementation:** lab profile update exposes `role` as writable. Reproduce as Bob: PATCH `/api/v1/profile` with `{"role":"admin"}`. **Observed:** response role changes from `user` to `admin`.

**Root cause:** a protected object attribute is included in the public update shape. **Business impact:** unauthorized privilege escalation where role-protected capabilities exist. **Remediation:** the secure profile schema strictly permits `name` only; registration does not accept a role either. Admin setup is controlled by seed code.

**Retest/regression:** API tests reject protected registration/profile fields with 400 and confirm the role remains `user`.

## SW-06 — Negative amount reverses the intended money flow

**Rule:** every transfer amount must be a positive integer paise value. **Severity: High**, because an ordinary request manipulates balances contrary to the transfer's meaning. Mapping: [CWE-20](https://cwe.mitre.org/data/definitions/20.html), used here as a general input-validation category.

**Vulnerable implementation:** `/api/v1/transfers/invalid-amount` accepts negative integers. Reproduce as Alice: send Bob `amount: -100`. **Observed:** HTTP 201; Alice rises from 100,000 to 100,100 paise, while Bob loses 100 paise.

**Root cause:** arithmetic is allowed without the positive-amount business invariant. **Business impact:** unauthorized reversal of value flow; fake balances only here. **Remediation:** strict positive integer validation with upper bounds, balance checks, and database transfer constraints.

**Retest/regression:** secure tests reject negative, zero, fractional-paise, string-valued, excessive and insufficient-funds requests, plus forged sender/self/unknown-recipient cases.

## SW-07 — Concurrent requests overspend one balance

**Rule:** concurrent transfers must not spend more than the available balance. **Severity: High**, because two authorized requests can violate balance integrity. Mapping: [CWE-362](https://cwe.mitre.org/data/definitions/362.html).

**Vulnerable implementation:** `/api/v1/transfers/race` reads without wallet locks. Reproduce through `lab:demo`: reset balances to 100,000 and send two requests of 70,000 with the same `X-Lab-Barrier` identifier. The two-party barrier releases only after both have read the old balance; it has a bounded timeout rather than arbitrary race sleeps.

**Observed:** both requests return 201 and the sender ends at **−40,000** paise. **Root cause:** the read/check/update sequence is not synchronized. **Business impact:** overspending and inconsistent payment authorization.

**Remediation:** secure transactions acquire both wallet locks in a consistent order and check balance under the lock. **Retest/regression:** the corresponding PostgreSQL test holds a lock until both requests are waiting; exactly one succeeds, the sender ends at 30,000, all ledger entries reconcile, and total funds are conserved.

## SW-08 — Retried request is processed twice

**Rule:** one sender, idempotency key and payload represents one payment. **Severity: High**, because network retries can duplicate an otherwise valid debit. Mapping: [CWE-837](https://cwe.mitre.org/data/definitions/837.html).

**Vulnerable implementation:** `/api/v1/transfers/retry` ignores `Idempotency-Key`. Reproduce: send the same 500-paise request twice with the same key after resetting Alice to 100,000. **Observed:** two different transfer IDs and an ending balance of 99,000.

**Root cause:** no durable coordination identifies the repeated intended action. **Business impact:** duplicate payments and customer disputes. **Remediation:** a sender-scoped unique key, normalized payload fingerprint, and committed result belong to the same transaction as the payment.

**Retest/regression:** secure tests cover repeated keys, concurrent identical keys, mismatched payloads, and separate sender scopes. Repetition returns the original transfer and debits only once.

## SW-09 — One exhausted authentication budget locks out every account

**Provenance: discovered during self-review of the secure implementation.** Not a planted flaw. Found by re-reading `auth.ts` against the threat model entry for password guessing and asking what `req.ip` actually contains at runtime.

**Rule:** authentication throttling must bound what one client can attempt, without letting one client bound what every other client can attempt. **Severity: High.** Mapping: [CWE-770](https://cwe.mitre.org/data/definitions/770.html), A04:2021. **CVSS v3.1 7.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. Availability is High because the denial covers sign-in, password change and password reset simultaneously: a locked-out user has no self-service route back in. No privileges are required, which is what carries the score.

**Vulnerable implementation:** `express-rate-limit` was configured with its default key generator, which buckets on `req.ip`. Express only derives `req.ip` from `X-Forwarded-For` when `trust proxy` is set, and it was never set. Every request reaches the API through the Next.js rewrite from `127.0.0.1`, so every request in the entire deployment hashed to the same bucket.

Reproduce against the pre-fix code: send 30 failed logins from one machine, then attempt a legitimate login as a different user from a different machine.

**Observed:** the second user receives `429 RATE_LIMITED` despite never having attempted a login. The 30-per-15-minute limit was a global budget, not a per-client one.

**Root cause:** the control was written against the value `req.ip` is _assumed_ to hold rather than the value it holds behind a proxy. The configuration looked correct in isolation and was silently inert in the deployed topology. This is the same class of mistake as SW-01 — trusting an identifier without checking what it actually identifies.

**Business impact:** an unauthenticated attacker denies authentication to the whole user base for 15 minutes at a time with roughly 30 requests, and sustains it indefinitely. It also quietly weakens the brute-force control the threat model claimed: a distributed attacker spreading guesses across addresses was never being counted per address in the first place.

**Remediation** — three parts, in `config.ts`, `app.ts` and the new `throttle.ts`:

1. `app.set("trust proxy", trustProxy)`, defaulting to `"loopback"`. Express then honours `X-Forwarded-For` only when the immediate TCP peer is loopback, which is exactly the local Next.js rewrite and nothing else.
2. A second limiter keyed on the **targeted account** rather than the source, so spreading guesses across many addresses no longer evades the limit. It sets `skipSuccessfulRequests`, so the legitimate owner signing in never spends the budget that protects them — without that, the account limiter would hand an attacker a cheaper lockout than the one just fixed.
3. `config.ts` refuses to boot in production with `TRUST_PROXY="true"`, because trusting every hop lets any client forge `X-Forwarded-For` and re-create the original bug with extra steps.

**Residual risk, stated plainly:** with `trust proxy` enabled, anything that can reach the API directly can still forge `X-Forwarded-For` and choose its own bucket. The API binds to loopback, so that means local access only. A real deployment terminates TLS at a proxy that overwrites the header rather than appending to it, and moves the counters to a shared store — the limiter is still process-local, so a second API instance would double every limit.

**Retest/regression:** `apps/api/tests/security.test.ts`, `SW-09 source and account throttling`. Four cases: two forwarded sources get independent budgets and exhausting one does not affect the other; ten failures against a single account are blocked even when every request arrives from a different address; a forged non-IP `X-Forwarded-For` is stored as NULL instead of failing the request; failed sign-ins are recorded for both known and unknown accounts while the response stays generic.

The last case matters beyond this finding: **the audit trail had no record of a failed sign-in at all**, because the failure threw inside the transaction and rolled its own audit row back. Nothing could have detected the attack even while it was succeeding. The login handler now returns the failure instead of throwing it, so the record commits, and DET-01 and DET-02 in `docs/DETECTION-RUNBOOK.md` are built on it.

## SW-10 — No Content-Security-Policy on the wallet interface

**Provenance: discovered during self-review of the secure implementation.** Found by comparing the headers the lab sets against the headers the secure application sets, and noticing the comparison ran the wrong way.

**Rule:** stored XSS is defended in depth. Escaping decides whether a payload becomes markup; a policy decides what that markup could do if escaping ever fails. **Severity: Medium.** Mapping: [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html), A05:2021.

**No independent CVSS score.** This is a missing mitigating control, not an exploitable weakness on its own: with React escaping intact there is no attack here to score. Assigning it a base vector would put a number in the register that no exploit corresponds to, and would double-count the risk already captured by SW-04. What it does is raise the effective severity of every future XSS-class defect, which is a statement about the register as a whole rather than about one row in it.

**Vulnerable implementation:** `apps/web/next.config.ts` set `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` and `Permissions-Policy` — and no `Content-Security-Policy`. The intentionally vulnerable lab did set one, specifically so its own XSS demonstration could not exfiltrate anything. The security control existed only on the deliberately insecure side of the project.

Reproduce against the pre-fix code: `curl -I http://localhost:3000/login` and look for the header.

**Observed:** absent. An injected inline event handler would have executed with no policy to stop it.

**Root cause:** the threat model treated XSS as closed because the rendering path was correct, so no second layer was specified. Defence in depth is a property of a system, not of a function, and reviewing one function at a time cannot show it is missing.

**Business impact:** none directly — no XSS is currently reachable in the secure application. The cost is that the next mistake in a rendering path would have had full effect rather than reduced effect, and there is no reason to believe the codebase is permanently free of that mistake.

**Remediation:** `apps/web/src/proxy.ts` sets a per-response policy with a fresh nonce. `script-src` carries `'self' 'nonce-…' 'strict-dynamic'`, so Next.js's own inline hydration scripts run and injected markup does not, without allowlisting any host. `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'` close the plugin, base-tag and framing routes around it. Next 16 renamed this file convention from `middleware.ts` to `proxy.ts`.

Two relaxations are deliberate and neither weakens `script-src`:

- `style-src 'unsafe-inline'`. React sets inline **style attributes**, and a style attribute cannot carry a nonce — only a `<style>` element can. Nonce-ing this directive blocks the application's own layout while stopping no attacker. Verified: it broke every page before being relaxed.
- `'unsafe-eval'` in development only, where React uses eval to rebuild server error stacks. Production responses omit it, along with `upgrade-insecure-requests` being added only outside development, where the demo is plain HTTP.

**What `strict-dynamic` does not do**, stated because it is easy to claim more than it delivers: a script created with `document.createElement` and appended is _not_ parser-inserted, so the policy permits it by design — a script that already ran is trusted to load its own chunks. The control is over **injected markup**, which is the actual stored-XSS vector in SW-04. An inline event handler such as `<img onerror=…>` requires `'unsafe-inline'` in `script-src`, and this policy never grants it.

**Retest/regression:** `tests/browser/headers.spec.ts`, desktop and mobile. The policy is asserted to be served, to contain `strict-dynamic`, `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`, and never `script-src 'self' 'unsafe-inline'`; the nonce is asserted to differ between two responses; the application is driven through a hydrated client route with zero CSP violations on the console; and an injected `<img onerror>` payload is asserted not to execute.

## SW-11 — A NUL byte in support text returns 500

**Provenance: found by the schema-driven fuzzer added in this round of work**, on its first run against the secure application. Not planted, and not something the hand-written tests would have reached — no one writes a test for U+0000 in a subject line.

**Rule:** malformed input is rejected with a 4xx by the application, not by the database driver. **Severity: Low.** Mapping: [CWE-20](https://cwe.mitre.org/data/definitions/20.html), A04:2021. **CVSS v3.1 4.3** — `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L`. Availability is Low, not None: the request fails and is cheap to repeat, but it costs one connection and one error, not the service.

**Vulnerable implementation:** every free-text field was validated for length and trimmed, and nothing rejected control characters. PostgreSQL cannot store code point 0 in a `text` value under any encoding, so the insert failed inside the driver and reached the generic error handler.

Reproduce: `POST /api/v1/tickets` with a JSON body whose `body` field contains the escape `�`.

**Observed:** `500 INTERNAL_ERROR`. The generic message means nothing leaked, so this is an error-handling defect rather than an information disclosure.

**Root cause:** validation was written against what the field means to a person — a subject is short text — and not against what the storage layer can physically represent. Length and trimming felt like complete string validation, and a whole class of byte values was never considered.

**Business impact:** low on its own. It matters as a signal: a 500 is the application saying it did not anticipate the input, and the next unanticipated input may not fail as harmlessly. It also generates unexplained error-log noise, which is exactly the background an attacker benefits from.

**Remediation:** `apps/api/src/validation.ts` provides `safeText` and `safeOptionalText`, applied to registration and profile names, ticket subjects and bodies, comment bodies and transfer notes. Tab, newline and carriage return remain valid so multi-line messages still work. The check is written as an explicit code-point scan rather than a regular expression so the boundary is legible.

The OpenAPI document was updated in the same change. Leaving it unchanged would have left the specification claiming the API accepts input that it now refuses — and the fuzzer caught precisely that drift on the following run, which is the loop working as intended.

**Retest/regression:** `apps/api/tests/security.test.ts`, `SW-11 control characters in stored text`. A NUL byte returns 400 and writes no row; a control character is rejected on ticket, profile and transfer-note fields; tab, newline and carriage return are still accepted and stored. The fuzz run then passes all three phases over 1113 generated cases.

## Minor hardening from the same review

Two smaller items were fixed alongside SW-09 and SW-10. Neither is tracked as a numbered finding: the first was not exploitable and the second was not a defect.

- **LIKE metacharacters were not escaped.** Transaction search passed user input as a bound parameter — so SW-03 was genuinely closed — but `%` and `_` are still pattern syntax _inside_ `LIKE`, so a search for `%` matched every row the user could already see. No authorisation boundary was crossed, which is why it is not a finding, but it made the filter behave differently from how it reads and forced a leading-wildcard scan. Input is now escaped with an explicit `ESCAPE` character, covered by a regression test asserting that `%` and `_` return nothing while a literal substring still matches.
- **Admin list statements were composed from fragments.** `pool.query(\`${sql} ORDER BY …\`)`was safe, because the fragment came only from a fixed map. It was also indistinguishable from real SQL string building to a reviewer and to the`sw-sql-string-interpolation` rule. Each entry is now a complete literal statement. The control did not change; its verifiability did.

## Retest interpretation

`lab:demo` succeeds only when the controlled insecure outcomes occur. `security:lab` exits 1 because the lab violates three authorization assertions; that failure is expected and is kept separate from the secure test suite. The secure regression counterpart has passed the implemented assertions. Neither result is a claim of complete OWASP coverage or universal security.
