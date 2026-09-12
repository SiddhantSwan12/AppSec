# Recorded walkthrough script

A five-to-six minute screen recording, linked from the top of the README. Most reviewers will not clone and run this project; a recording is the only version of it many people will ever see.

Record at 1920×1080, editor font at 16pt or larger so code is readable at half size. No face camera needed. Speak over it live rather than reading — the wording below is the argument, not a teleprompter.

## Before recording

```
docker compose up -d --wait db mail
npm run db:reset -- --confirm-local-reset     # clean balances, predictable numbers
npm run dev
```

Open, in order: README, `apps/api/src/transfers.ts`, the test file at the concurrency case, `docs/FINDINGS.md` at SW-09, `docs/evidence/semgrep-verification.json`. Close every unrelated tab. Wait out any authentication throttle from rehearsals before the take.

---

## 0:00–0:30 — What it is

> "SecureWallet is a digital wallet I built to learn application security. It moves fake rupees between accounts, and the interesting part isn't the UI — it's that money movement has invariants a test can actually check. No balance goes negative. No transfer is ever half-applied. A retried request never pays twice.
>
> Alongside it there's an isolated lab with eight deliberately introduced flaws, so I could practise the full loop: reproduce, explain the impact, fix it, and prove the fix holds."

**On screen:** README top, then the architecture diagram.

Say "fake rupees" in the first fifteen seconds. Everything after is heard differently once that is established.

## 0:30–1:30 — The money invariant

**On screen:** `apps/api/src/transfers.ts`, scrolling slowly through the transaction.

> "This is the whole transfer. One database transaction on one checked-out connection — that matters, because using the pool inside the callback would put statements on different connections and the rollback would only cover part of the work.
>
> Both wallet rows get locked in ascending ID order. Always the same order, so two transfers in opposite directions can't deadlock. The balance is read _after_ the lock, not before — that ordering is the entire difference between correct and exploitable.
>
> And the idempotency key is claimed inside the same transaction as the debit. If the payment rolls back, the key claim rolls back with it, so a retry isn't rejected as a duplicate of something that never happened."

## 1:30–2:30 — Proving it, not asserting it

**On screen:** the concurrency test, then `npm test` running.

> "Anyone can claim that. This test proves it. It starts two transfers of 70,000 from a balance of 100,000 and holds a PostgreSQL lock until `pg_stat_activity` shows both requests actually waiting on it — a real barrier, not a sleep that passes on a fast machine and fails in CI.
>
> Exactly one succeeds. The sender ends at 30,000. Every ledger entry reconciles, and total funds across all wallets are unchanged — because the ledger is double-entry, so I can reconstruct any balance independently and check the two agree."

Let the suite finish on screen. Thirty-six passing tests is worth the silence.

## 2:30–3:30 — Finding my own bugs

**On screen:** `docs/FINDINGS.md` at the severity register, scrolled to SW-09.

> "Eight of these findings I planted on purpose. Three I didn't.
>
> SW-09 is the one I'd want to be asked about. I had rate limiting on authentication — thirty attempts per fifteen minutes, keyed on client IP. It looked right in review. It did nothing, because every request reaches the API through a Next.js rewrite from 127.0.0.1, and Express only derives `req.ip` from `X-Forwarded-For` when you set `trust proxy`, which I hadn't.
>
> So it wasn't a per-client limit at all. It was one global budget for the entire application. About thirty requests from one attacker and nobody can sign in, change a password, or reset one — the worst thing an unauthenticated attacker could do to this app needed no exploit and no account."

**On screen:** the fix — `trust proxy` in `app.ts`, then `throttle.ts`.

> "The fix is three parts. Trust the loopback proxy so `req.ip` is real. Add a second limiter keyed on the _targeted account_, so spreading guesses across addresses doesn't evade it. And skip successful requests on that one — otherwise I'd have handed an attacker a cheaper lockout than the one I just fixed."

That last sentence is the point of the whole segment: the obvious fix introduced a new problem, and noticing that is the skill.

## 3:30–4:30 — Detection, not just prevention

**On screen:** Admin → Detections, then `docs/DETECTION-RUNBOOK.md`.

> "Fixing SW-09 turned up something worse. Failed logins were never recorded at all — the handler threw on bad credentials, and the throw rolled back the transaction that would have written the audit row. The audit trail had every successful login and no failures. The single event most worth detecting was guaranteed to be missing.
>
> So I built five detection rules on that trail. Brute force against one account. One source spraying across many — which is the first rule's blind spot, deliberately. Reset flooding. Transfer velocity, where every individual request is authorised and only the pattern is wrong. And authorisation probing, which fires on requests the access controls already refused.
>
> Each one carries its response step, because an alert without a next action is just noise."

## 4:30–5:15 — Guardrails

**On screen:** `semgrep/rules/securewallet.yml`, then `npm run semgrep:verify` output.

> "Every finding is also a Semgrep rule. But a rule nobody tested is decoration — so the lab doubles as a labelled corpus. This script asserts two things: every rule fires on the lab, and no rule fires on the secure app. Nine for nine, zero findings on the secure side, and CI fails on either half.
>
> Writing these changed the code twice. The SQL rule flagged my admin list queries — they were safe, the fragment came from a fixed map, but they were indistinguishable from real string building, so I wrote them out as complete statements. And I added the role guard to each admin route as well as the router, so the control is locally visible. Neither was a vulnerability. Both made the control checkable instead of needing to be argued."

## 5:15–6:00 — Honest close

**On screen:** `docs/ASVS.md` summary table, then the residual risk register.

> "ASVS Level 1 self-assessment: 48 requirements met, 5 partial, 2 not met. The two gaps are TLS and MFA, and both are deployment decisions I'm not pretending to have made.
>
> The residual risk register is the part I'd want read closely. Rate limiting is still process-local. The demo database runs as a superuser. Detection thresholds are reasoned, not measured against real traffic. Response timing isn't normalised, so enumeration resistance is partial.
>
> The tests prove the cases I wrote held. They don't prove there's nothing else — and a project that claimed otherwise would be making exactly the mistake that produced SW-09."

---

## Notes

**Do not demo the vulnerable lab in the recording.** It needs setup and disclaimers that cost a minute and buy nothing — the lab's value here is as the corpus that proves the Semgrep rules work, which the 4:30 segment already shows. Keep it for a live conversation where someone asks.

**Lead with the invariant, not the eight flaws.** "I planted eight OWASP bugs" reads as coursework. "I built a payment path with correctness invariants and proved them under real concurrency" reads as engineering. Same project.

**If it runs long, cut the guardrails segment to thirty seconds.** Do not cut the 2:30 segment. Finding real bugs in your own finished code is the most persuasive minute in the recording.
