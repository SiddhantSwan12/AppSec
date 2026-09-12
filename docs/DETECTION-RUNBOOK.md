# Detection and response runbook

Prevention decides whether an attack succeeds. Detection decides whether anyone finds out it was attempted. This project had the second half available and unused: `audit_events` was being written and never read.

Five rules now run over that trail. They are defined in `apps/api/src/detections.ts`, evaluated on request by `GET /api/v1/admin/detections`, and shown to administrators under **Admin → Detections**.

## Design notes

**The rules query the audit trail, not the live request path.** A detection that runs inline adds latency to the thing it is watching and fails when the request fails. Reading committed events afterwards means a rule can be added, changed or removed without touching the money path.

**Every rule is a threshold over a window, expressed in SQL, with exactly two bound parameters.** The statement comes from a fixed table in code; only the window and threshold are bound. Adding a rule means adding a row, not adding a code path.

**A rule reports a subject, a count and a last-seen time.** Not a verdict. The response step is a human decision, which is why each rule carries the step rather than automating it.

**Recording a denial is not the same as preventing one.** DET-05 fires on requests the access controls already refused. Those refusals are the system working; a burst of them is someone learning what they cannot reach.

### The gap this exposed

DET-01 and DET-02 could not have worked before SW-09 was fixed, for a reason that had nothing to do with rate limiting: **failed sign-ins were never recorded at all.** The login handler threw an `ApiError` on bad credentials, and the throw rolled back the transaction that would have written the audit row along with it. The audit trail recorded every successful login and no failures — so the one event most worth detecting was the one event guaranteed to be missing.

The handler now returns the failure instead of throwing it, so the record commits before the 401 is raised.

## Rules

| ID     | Signal                                      | Window | Threshold  | Severity |
| ------ | ------------------------------------------- | ------ | ---------- | -------- |
| DET-01 | Failed sign-ins against one account         | 15 min | 5          | High     |
| DET-02 | One source failing against several accounts | 15 min | 3 accounts | High     |
| DET-03 | Password reset requests for one account     | 60 min | 3          | Medium   |
| DET-04 | Completed transfers from one account        | 5 min  | 10         | High     |
| DET-05 | Denied requests from one signed-in account  | 15 min | 5          | Medium   |

### DET-01 — Repeated failed sign-ins against one account

Password guessing aimed at a single account. The account throttle already slows it; this reports that it is happening, which the throttle does not.

**Respond:** confirm whether the owner is present and simply mistyping — a support ticket or a successful sign-in from the same source shortly after is usually enough. If not, force a password reset and revoke that user's sessions (`DELETE FROM sessions WHERE user_id = …`). Check whether any attempt succeeded before you intervened.

**False positives:** a genuine user with a password manager mismatch. Expect these; the response step is designed to be cheap.

### DET-02 — One source guessing across several accounts

Credential stuffing spreads a handful of guesses over many accounts precisely so no single account trips DET-01. The counterpart to DET-01 rather than a duplicate of it: DET-01 groups by account, DET-02 groups by source and counts distinct accounts.

**Respond:** block the source at the edge. Then check whether any account in the set signed in successfully afterwards — a successful login from an address that was spraying is the finding that matters, and it will not raise an alert of its own.

**Limitation, stated plainly:** grouping by source address is defeated by rotating addresses. It catches the cheap version of this attack, not the patient one.

### DET-03 — Repeated password reset requests for one account

Reset flooding precedes takeover attempts and is a nuisance to the owner. Recorded for every request, including for addresses with no account, so the rule sees the attempt without the public response revealing whether the account exists.

**Respond:** verify no reset token was consumed (`used_at IS NOT NULL` on a recent row). If one was, treat the account as compromised: revoke sessions, force a reset, and review activity since the consumption.

### DET-04 — Unusual transfer velocity from one account

Every transfer counted here was authorised, correctly validated and correctly recorded. The pattern is the signal, not any individual request — this is what an account draining looks like after credentials are stolen, and no per-request control will ever see it.

**Respond:** hold further transfers for the account, contact the owner through a channel that is not the account, and reconcile the ledger for the window. Because the ledger is double-entry, `SELECT sum(amount) FROM ledger WHERE wallet_id = …` reconstructs the balance independently of the `wallets` row.

### DET-05 — Authorisation probing by a signed-in account

Fires on 403 and 404 responses to authenticated requests. A handful is normal — a stale link, a deleted ticket. A cluster from one account is someone iterating identifiers.

**Respond:** review which resources were denied. Repeated identifier guessing against other users' records justifies suspending the account. This is the live counterpart to SW-01: if the ownership predicate ever regresses, this rule shows someone finding out before the regression does damage.

## What is deliberately not here

**No alerting.** The rules are evaluated when an administrator opens the page. A real deployment runs them on a schedule and pushes to a channel someone actually watches. A dashboard nobody opens is not detection.

**No suppression or deduplication.** The same condition reports on every evaluation until it ages out of its window. Real alerting needs state so that one incident does not generate a hundred notifications.

**No tuning against real traffic.** Every threshold is a reasoned guess, not a measured one. Thresholds should come from a baseline of normal behaviour; there is no production traffic here to baseline against.

**Audit rows are not tamper-proof.** They are append-only by convention. The demo database connects as a superuser, so nothing stops rows being deleted. Least-privilege grants would be the first fix, and shipping events off-host the second.

## Privacy note

`audit_events.source_ip` stores a client address, which is personal data in most jurisdictions. It is here because DET-02 cannot work without it. A real deployment needs a retention period and a deletion job; this project has neither, which is recorded as a limitation rather than solved. Forged or malformed values are stored as NULL rather than rejected, so a bad header cannot fail the request it is attached to.

## Verification

`apps/api/tests/security.test.ts`, `detection rules over the audit trail`:

- a rule stays silent one event below its threshold and fires on it
- spraying across three accounts raises DET-02 while no account reaches DET-01's threshold, proving the two rules are not restatements of each other
- five denied ticket reads raise DET-05, and the response to the denied user is unchanged
- the feed returns 403 to a normal user and 401 to an anonymous caller
