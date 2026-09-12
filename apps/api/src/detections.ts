import { pool } from "./db.js";

/**
 * Detection rules read the audit trail that the application already writes.
 * Prevention is the first control; these rules answer the separate question of
 * whether someone is currently trying. Each rule names the response step that
 * docs/DETECTION-RUNBOOK.md expands on.
 *
 * Every rule returns `subject`, `count` and `last_seen`, and takes exactly two
 * bound parameters: the window in minutes and the threshold.
 */
export type Severity = "high" | "medium" | "low";
export type Rule = {
  id: string;
  title: string;
  severity: Severity;
  windowMinutes: number;
  threshold: number;
  rationale: string;
  response: string;
  sql: string;
};

export const rules: Rule[] = [
  {
    id: "DET-01",
    title: "Repeated failed sign-ins against one account",
    severity: "high",
    windowMinutes: 15,
    threshold: 5,
    rationale:
      "Password guessing aimed at a single account. The account throttle slows it; this reports that it is happening.",
    response:
      "Confirm whether the owner is present. If not, force a password reset and revoke that user's sessions.",
    sql: `SELECT COALESCE(u.email,'(no matching account)') AS subject,
                 count(*)::int AS count, max(a.created_at) AS last_seen
            FROM audit_events a LEFT JOIN users u ON u.id = a.user_id
           WHERE a.event = 'auth.login_failed'
             AND a.created_at > now() - make_interval(mins => $1::int)
        GROUP BY 1 HAVING count(*) >= $2::int
        ORDER BY count(*) DESC LIMIT 50`,
  },
  {
    id: "DET-02",
    title: "One source guessing across several accounts",
    severity: "high",
    windowMinutes: 15,
    threshold: 3,
    rationale:
      "Credential stuffing spreads a few guesses over many accounts, so no single account trips DET-01.",
    response:
      "Block the source at the edge, then check whether any account in the set signed in successfully afterwards.",
    sql: `SELECT host(a.source_ip) AS subject,
                 count(DISTINCT COALESCE(a.user_id::text,'unknown'))::int AS count,
                 max(a.created_at) AS last_seen
            FROM audit_events a
           WHERE a.event = 'auth.login_failed' AND a.source_ip IS NOT NULL
             AND a.created_at > now() - make_interval(mins => $1::int)
        GROUP BY 1 HAVING count(DISTINCT COALESCE(a.user_id::text,'unknown')) >= $2::int
        ORDER BY count(*) DESC LIMIT 50`,
  },
  {
    id: "DET-03",
    title: "Repeated password reset requests for one account",
    severity: "medium",
    windowMinutes: 60,
    threshold: 3,
    rationale:
      "Reset flooding precedes takeover attempts and mailbox compromise, and is also a nuisance to the owner.",
    response:
      "Verify no reset token was consumed. If one was, treat the account as compromised and revoke sessions.",
    sql: `SELECT COALESCE(u.email,'(no matching account)') AS subject,
                 count(*)::int AS count, max(a.created_at) AS last_seen
            FROM audit_events a LEFT JOIN users u ON u.id = a.user_id
           WHERE a.event = 'auth.password_reset_requested'
             AND a.created_at > now() - make_interval(mins => $1::int)
        GROUP BY 1 HAVING count(*) >= $2::int
        ORDER BY count(*) DESC LIMIT 50`,
  },
  {
    id: "DET-04",
    title: "Unusual transfer velocity from one account",
    severity: "high",
    windowMinutes: 5,
    threshold: 10,
    rationale:
      "Every individual transfer is authorised and correct. The pattern, not the request, is the signal that an account is draining.",
    response:
      "Hold further transfers for the account, contact the owner, and reconcile the ledger for the window.",
    sql: `SELECT COALESCE(u.email, a.user_id::text) AS subject,
                 count(*)::int AS count, max(a.created_at) AS last_seen
            FROM audit_events a LEFT JOIN users u ON u.id = a.user_id
           WHERE a.event = 'transfer.completed'
             AND a.created_at > now() - make_interval(mins => $1::int)
        GROUP BY 1 HAVING count(*) >= $2::int
        ORDER BY count(*) DESC LIMIT 50`,
  },
  {
    id: "DET-05",
    title: "Authorisation probing by a signed-in account",
    severity: "medium",
    windowMinutes: 15,
    threshold: 5,
    rationale:
      "Denied requests mean the controls held. A burst of them means someone is mapping what they cannot reach.",
    response:
      "Review the denied resources. Repeated identifier guessing against other users' records justifies suspending the account.",
    sql: `SELECT COALESCE(u.email, a.user_id::text) AS subject,
                 count(*)::int AS count, max(a.created_at) AS last_seen
            FROM audit_events a LEFT JOIN users u ON u.id = a.user_id
           WHERE a.event = 'authz.denied' AND a.user_id IS NOT NULL
             AND a.created_at > now() - make_interval(mins => $1::int)
        GROUP BY 1 HAVING count(*) >= $2::int
        ORDER BY count(*) DESC LIMIT 50`,
  },
];

export type Alert = {
  id: string;
  rule: string;
  title: string;
  severity: Severity;
  subject: string;
  count: number;
  last_seen: string;
  window_minutes: number;
  threshold: number;
  response: string;
};

const order: Record<Severity, number> = { high: 0, medium: 1, low: 2 };

export async function evaluate(): Promise<Alert[]> {
  const alerts: Alert[] = [];
  for (const rule of rules) {
    // SQL comes only from the rule table above; the window and threshold are
    // the sole bound parameters.
    const rows = (
      await pool.query(rule.sql, [rule.windowMinutes, rule.threshold])
    ).rows as { subject: string; count: number; last_seen: Date }[];
    for (const row of rows)
      alerts.push({
        id: `${rule.id}:${row.subject}`,
        rule: rule.id,
        title: rule.title,
        severity: rule.severity,
        subject: row.subject,
        count: row.count,
        last_seen: new Date(row.last_seen).toISOString(),
        window_minutes: rule.windowMinutes,
        threshold: rule.threshold,
        response: rule.response,
      });
  }
  return alerts.sort(
    (a, b) =>
      order[a.severity] - order[b.severity] ||
      b.last_seen.localeCompare(a.last_seen),
  );
}
