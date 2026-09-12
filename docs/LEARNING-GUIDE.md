# Learn SecureWallet by tracing the code

Do not try to memorize the whole repository. Run one flow, find the code that handles it, change a controlled input, and explain the result before moving on. Use fake local accounts only.

## 1. Follow one login request

Read `apps/web/src/lib/api.ts`, then `apps/api/src/auth.ts`, then `apps/api/src/security.ts`.

The browser first asks for a CSRF token. Login sends JSON plus the token. Express checks Origin and CSRF, validates fields, loads the user by a parameterized email query, and verifies the Argon2id hash. It creates a random session credential and stores only its SHA-256 digest. The raw credential goes into an HttpOnly cookie. The next authenticated request hashes that cookie and resolves the user from PostgreSQL.

Explain aloud: **a password hash verifies a password; a session associates later requests with a user without resending that password.** Clearing a browser cookie alone would not invalidate a stolen copy; deleting the server session does.

Exercise: sign out, then run the logout regression test. Explain why replaying the old cookie returns 401. Never paste session credentials into your report.

## 2. Distinguish authentication from authorization

Read ticket and transaction routes in `apps/api/src/app.ts` and the matrix in `AUTHORIZATION.md`.

Authentication answers “who is making this request?” Authorization answers “may that person perform this operation on this record?” A valid Bob session does not grant access to Alice's ticket. The query includes both record ID and owner ID; the admin support exception is deliberate and documented.

Exercise: run `npm run security:run`, then open the HTML report. Explain why the runner checks response content as well as status. A 404 response containing Alice's ticket would still leak it.

Interview question: “Would UUIDs fix IDOR?” Answer: no. Hard-to-guess identifiers do not replace an ownership check.

## 3. Understand the transfer transaction

Read `apps/api/src/transfers.ts` beside `apps/api/src/db.ts`.

The main invariant is that the two wallet changes and their ledger entries describe the same movement. `BEGIN` starts a transaction; `COMMIT` publishes all changes; `ROLLBACK` discards them. Every query must use the callback's `db` connection.

Exercise: find the test that installs a temporary ledger-insert failure in the dedicated test DB. It checks balances, transfer count, and idempotency rows after failure. Explain why “the endpoint returned 500” alone would not prove rollback.

Amounts are integers: ₹700 means 70,000 paise. The form parses rupee text using BigInt; it does not trust binary floating-point arithmetic for conversion. PostgreSQL returns bigint amounts as strings, preserving exact integers across JSON.

## 4. Separate atomicity, locking, and idempotency

- Atomicity prevents half a payment.
- Row locks prevent two requests spending the same available balance at once.
- An idempotency key prevents a retry from executing the same intended payment twice.

Transactions alone do not make an unsafe read-check-write sequence correct. Our check occurs after locking both wallets. Both directions lock by wallet ID, preventing opposing transfers from acquiring the locks in reverse order.

Exercise: run `npm test` and locate the 100,000 / 70,000 concurrency test. It holds a database lock until both requests are observably waiting, then releases them. One succeeds, one rejects, the sender ends with 30,000, and total funds remain unchanged. The vulnerable demonstration uses a two-party barrier so both requests see the old balance; the sender ends negative.

The unique `(sender_id,key)` index coordinates identical concurrent requests. A conflicting insert waits. After the first commit, the second request reads the saved result. A changed payload with the same key returns 409. The same key from another sender is independent.

Interview question: “What if the response is lost after commit?” Answer: retry the same key and normalized payload to obtain the committed result. The browser keeps the key during the open confirmation; recovery after tab closure remains a documented limitation.

## 5. Demonstrate, fix, and retest a vulnerability

Read one scenario in `apps/api/src/lab/server.ts`, its entry in `FINDINGS.md`, and the secure counterpart. Run `npm run lab:demo` to obtain fresh evidence.

For SQL injection, compare string interpolation in the isolated fixture with `$1`, `$2` parameters in the secure API. Parameters separate SQL structure from data. For stored XSS, compare raw HTML insertion in the fixture with React's `{c.body}` text rendering. The harmless demo only changes a DOM marker; it does not extract data or contact another service.

For mass assignment, see how the lab exposes `role` as writable while the secure profile schema accepts only `name`. Validation must describe which fields may change, not merely whether a JSON object has a plausible shape.

Use this explanation pattern: rule → controlled request → observed response → root cause → impact → fix → retest. These flaws were intentionally introduced for education, not discovered in a real company.

## 6. Describe what you actually verified

Read `PROGRESS.md` and the generated reports. Distinguish integration tests, browser tests, and configured authorization regression checks. The Python tool does not crawl arbitrary targets or discover every vulnerability.

Useful questions to practice:

1. Why are sessions stored server-side? How does logout invalidate them?
2. Why is HttpOnly useful, and why does it not make XSS harmless?
3. Why do cookie-authenticated writes need CSRF protection?
4. Where is ownership checked for a transaction and a support ticket?
5. Why are the debit, credit, ledger and key result in one transaction?
6. What does a unique index contribute to idempotency under concurrency?
7. How do seed credits differ from normal transfers?
8. What is still needed before deploying a real wallet?

Answer from the implementation and test results. Say “this project demonstrates these controls” rather than “this application is completely secure.”
