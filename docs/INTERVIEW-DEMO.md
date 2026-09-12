# Five-minute interview demonstration

Prepare: run the secure app and lab, generate reports, and open the relevant source files. Use seeded fake accounts only. If needed, explicitly reset local demo data before the interview; do not reset while presenting.

| Time      | Show                                              | Explain                                                                                                                                                                          |
| --------- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0:00–0:40 | README and architecture diagram                   | A full-stack fake wallet plus a separate deliberately vulnerable lab. You implemented it to learn security assessment and remediation.                                           |
| 0:40–1:20 | Alice login, dashboard and one small transfer     | Session cookie resolves identity; the browser cannot choose sender or balance. Money uses integer paise.                                                                         |
| 1:20–2:00 | `transfers.ts` and the concurrency test           | Same-connection transaction, deterministic row locks, balance check under lock. Two requests for 70,000 from 100,000 produce only one successful transfer.                       |
| 2:00–2:45 | Lab BOLA evidence and secure authorization report | Bob can read Alice's lab ticket. The secure query adds ownership; the retest denies Bob while allowing Alice/admin. Explain business impact.                                     |
| 2:45–3:30 | One stored-XSS or SQL-injection finding           | Trace input to the unsafe sink, show the harmless observed outcome, then the secure text rendering or parameterized query.                                                       |
| 3:30–4:15 | Idempotency test and runner                       | A repeated key/payload returns the original result; changed payload fails. The Python tool checks configured rules and response content, with separate failure/setup exit codes. |
| 4:15–5:00 | PROGRESS, findings and limitations                | Explain what actually passed, the expected lab failures, and what a production system would still need.                                                                          |

Useful opening: “I built a local digital wallet with fake funds, then isolated eight intentionally vulnerable scenarios to practice reproducing a flaw, explaining its impact, implementing the secure counterpart, and retesting it.”

If asked something you cannot explain, follow the relevant request through the code and test. Do not call this a universal scanner, a real banking system, a real-company assessment, or a guarantee of security.
