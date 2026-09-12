import {
  beforeAll,
  beforeEach,
  afterAll,
  describe,
  it,
  expect,
  vi,
} from "vitest";
import request from "supertest";
import { randomUUID } from "node:crypto";
import { app } from "../src/app.js";
import { pool } from "../src/db.js";
import { migrate } from "../src/migrate.js";
import { seed, demoIds } from "../src/seed.js";
import { hashToken, sessionCookie } from "../src/security.js";

const password = process.env.DEMO_PASSWORD!;
const origin = process.env.APP_ORIGIN!;
beforeAll(async () => {
  await migrate();
});
beforeEach(async () => {
  await pool.query(
    "TRUNCATE audit_events,comments,tickets,ledger,idempotency,transfers,reset_tokens,sessions,wallets,users RESTART IDENTITY CASCADE",
  );
  await seed();
});
afterAll(async () => {
  await pool.end();
});
async function actor(name = "alice") {
  const agent = request.agent(app);
  let csrf = (await agent.get("/api/v1/auth/csrf")).body.csrfToken;
  const result = await agent
    .post("/api/v1/auth/login")
    .set("Origin", origin)
    .set("X-CSRF-Token", csrf)
    .send({ email: `${name}@example.test`, password });
  expect(result.status).toBe(200);
  csrf = result.body.csrfToken;
  const cookies = result.headers["set-cookie"] as unknown as string[];
  const session = cookies
    .find((c) => c.startsWith(`${sessionCookie}=`))!
    .split(";")[0];
  return {
    agent,
    csrf,
    session,
    post: (path: string, body: unknown, key = randomUUID()) =>
      agent
        .post(`/api/v1${path}`)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .set("Idempotency-Key", key)
        .send(body),
  };
}
async function balances() {
  return (
    await pool.query("SELECT user_id,balance FROM wallets ORDER BY user_id")
  ).rows;
}
async function assertLedger() {
  const mismatches = await pool.query(
    "SELECT w.id FROM wallets w LEFT JOIN ledger l ON l.wallet_id=w.id GROUP BY w.id HAVING w.balance<>COALESCE(sum(l.amount),0)",
  );
  expect(mismatches.rowCount).toBe(0);
  const unbalanced = await pool.query(
    "SELECT transfer_id FROM ledger WHERE transfer_id IS NOT NULL GROUP BY transfer_id HAVING sum(amount)<>0 OR count(*)<>2",
  );
  expect(unbalanced.rowCount).toBe(0);
}
async function releaseWhenBlocked(
  blocker: import("pg").PoolClient,
  count: number,
) {
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    const waiting = await pool.query(
      "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND pid<>pg_backend_pid()",
    );
    if (Number(waiting.rows[0].count) >= count) {
      await blocker.query("COMMIT");
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  await blocker.query("ROLLBACK");
  throw new Error(
    "Concurrency barrier did not observe both requests waiting on PostgreSQL locks.",
  );
}
describe("authentication and permissions", () => {
  it("throttles authentication attempts outside test bypass mode", async () => {
    const agent = request.agent(app);
    const csrf = (await agent.get("/api/v1/auth/csrf")).body.csrfToken;
    vi.stubEnv("NODE_ENV", "development");
    try {
      for (let i = 0; i < 30; i++)
        expect(
          (
            await agent
              .post("/api/v1/auth/login")
              .set("Origin", origin)
              .set("X-CSRF-Token", csrf)
              .send({})
          ).status,
        ).toBe(400);
      expect(
        (
          await agent
            .post("/api/v1/auth/login")
            .set("Origin", origin)
            .set("X-CSRF-Token", csrf)
            .send({})
        ).status,
      ).toBe(429);
    } finally {
      vi.unstubAllEnvs();
    }
  });
  it("registers a normal user with a zero balance and no cleartext password", async () => {
    const a = await actor();
    const email = "new@example.test";
    expect(
      (await a.post("/auth/register", { name: "New user", email, password }))
        .status,
    ).toBe(201);
    const row = (
      await pool.query(
        "SELECT u.role,u.password_hash,w.balance FROM users u JOIN wallets w ON w.user_id=u.id WHERE email=$1",
        [email],
      )
    ).rows[0];
    expect(row.role).toBe("user");
    expect(row.password_hash).toMatch(/^\$argon2id\$/);
    expect(row.balance).toBe("0");
  });
  it("rejects public role assignment and protected profile fields", async () => {
    const a = await actor();
    expect(
      (
        await a.post("/auth/register", {
          name: "Bad",
          email: "bad@example.test",
          password,
          role: "admin",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await a.agent
          .patch("/api/v1/profile")
          .set("Origin", origin)
          .set("X-CSRF-Token", a.csrf)
          .send({ name: "Alice", role: "admin" })
      ).status,
    ).toBe(400);
    expect((await a.agent.get("/api/v1/auth/me")).body.user.role).toBe("user");
  });
  it("uses generic login errors and rejects incorrect passwords", async () => {
    const a = await actor();
    const known = await a.post("/auth/login", {
      email: "alice@example.test",
      password: "incorrect",
    });
    const unknown = await a.post("/auth/login", {
      email: "missing@example.test",
      password: "incorrect",
    });
    expect(known.status).toBe(401);
    expect(known.body).toEqual(unknown.body);
  });
  it("sets HttpOnly SameSite cookies and invalidates the server session on logout", async () => {
    const a = await actor();
    expect((await a.post("/auth/logout", {})).status).toBe(200);
    expect(
      (await request(app).get("/api/v1/wallet").set("Cookie", a.session))
        .status,
    ).toBe(401);
    expect(
      (await pool.query("SELECT count(*) FROM sessions")).rows[0].count,
    ).toBe("0");
    const result = await a.agent.get("/api/v1/auth/csrf");
    expect(result.headers["set-cookie"][0]).toContain("HttpOnly");
    expect(result.headers["set-cookie"][0]).toContain("SameSite=Strict");
  });
  it("rejects expired sessions", async () => {
    const a = await actor();
    await pool.query(
      "UPDATE sessions SET expires_at=now()-interval '1 second'",
    );
    expect((await a.agent.get("/api/v1/wallet")).status).toBe(401);
  });
  it("rejects absent CSRF, absent origin, and hostile origin", async () => {
    const a = await actor();
    expect(
      (await a.agent.post("/api/v1/auth/logout").set("Origin", origin).send({}))
        .status,
    ).toBe(403);
    expect(
      (
        await a.agent
          .post("/api/v1/auth/logout")
          .set("X-CSRF-Token", a.csrf)
          .send({})
      ).status,
    ).toBe(403);
    expect(
      (
        await a.agent
          .post("/api/v1/auth/logout")
          .set("Origin", "https://attacker.invalid")
          .set("X-CSRF-Token", a.csrf)
          .send({})
      ).status,
    ).toBe(403);
  });
  it("enforces anonymous, owner, other-user, and admin access to tickets", async () => {
    const alice = await actor();
    const bob = await actor("bob");
    const admin = await actor("admin");
    const path = `/api/v1/tickets/${demoIds.ticket}`;
    expect((await request(app).get(path)).status).toBe(401);
    expect((await alice.agent.get(path)).body.ticket.user_id).toBe(
      demoIds.alice,
    );
    const denied = await bob.agent.get(path);
    expect(denied.status).toBe(404);
    expect(JSON.stringify(denied.body)).not.toContain("question about");
    expect((await admin.agent.get(path)).body.ticket.id).toBe(demoIds.ticket);
  });
  it("enforces role checks across every admin list and ticket mutation", async () => {
    const a = await actor();
    const admin = await actor("admin");
    for (const path of ["users", "transactions", "tickets", "audit-events"]) {
      expect((await a.agent.get(`/api/v1/admin/${path}`)).status).toBe(403);
      expect((await admin.agent.get(`/api/v1/admin/${path}`)).status).toBe(200);
    }
    expect(
      (
        await a.agent
          .patch(`/api/v1/admin/tickets/${demoIds.ticket}`)
          .set("Origin", origin)
          .set("X-CSRF-Token", a.csrf)
          .send({ status: "closed" })
      ).status,
    ).toBe(403);
  });
  it("changes passwords and invalidates every session", async () => {
    const a = await actor();
    const second = await actor();
    expect(
      (
        await a.post("/auth/password", {
          currentPassword: password,
          newPassword: "New-password-for-test!",
        })
      ).status,
    ).toBe(200);
    expect((await second.agent.get("/api/v1/wallet")).status).toBe(401);
  });
  it("rejects expired reset tokens, consumes valid ones once, and revokes sessions", async () => {
    const a = await actor();
    const raw = "x".repeat(43);
    await pool.query(
      "INSERT INTO reset_tokens(token_hash,user_id,expires_at) VALUES($1,$2,now()-interval '1 second')",
      [hashToken(raw), demoIds.alice],
    );
    expect(
      (
        await a.post("/auth/reset-password", {
          token: raw,
          newPassword: "New-password-for-test!",
        })
      ).status,
    ).toBe(400);
    await pool.query(
      "UPDATE reset_tokens SET expires_at=now()+interval '1 minute'",
    );
    expect(
      (
        await a.post("/auth/reset-password", {
          token: raw,
          newPassword: "New-password-for-test!",
        })
      ).status,
    ).toBe(200);
    expect(
      (await request(app).get("/api/v1/wallet").set("Cookie", a.session))
        .status,
    ).toBe(401);
    expect(
      (
        await a.post("/auth/reset-password", {
          token: raw,
          newPassword: "New-password-for-test!",
        })
      ).status,
    ).toBe(400);
  });
  it("supports owner comments, admin replies and closing; rejects non-owner comments", async () => {
    const a = await actor();
    const b = await actor("bob");
    const admin = await actor("admin");
    const path = `/tickets/${demoIds.ticket}`;
    const body = '<img src=x onerror="window.__xss=true">';
    expect((await a.post(`${path}/comments`, { body })).status).toBe(201);
    expect(
      (await b.post(`${path}/comments`, { body: "Intrusion" })).status,
    ).toBe(404);
    expect(
      (await admin.post(`${path}/comments`, { body: "Support reply" })).status,
    ).toBe(201);
    const response = await a.agent.get(`/api/v1${path}`);
    expect(
      response.body.comments.map((c: { body: string }) => c.body),
    ).toContain(body);
    await admin.agent
      .patch(`/api/v1/admin/tickets/${demoIds.ticket}`)
      .set("Origin", origin)
      .set("X-CSRF-Token", admin.csrf)
      .send({ status: "closed" })
      .expect(200);
    expect(
      (await a.post(`${path}/comments`, { body: "Closed reply" })).status,
    ).toBe(409);
  });
});
describe("financial integrity with real PostgreSQL", () => {
  it.each([-1, 0, 0.5, 100000001, "70000"])(
    "rejects invalid amount %s",
    async (amount) => {
      const a = await actor();
      expect(
        (await a.post("/transfers", { recipientId: demoIds.bob, amount }))
          .status,
      ).toBe(400);
      await assertLedger();
    },
  );
  it("rejects insufficient funds, self transfers, unknown recipients and sender override", async () => {
    const a = await actor();
    expect(
      (await a.post("/transfers", { recipientId: demoIds.bob, amount: 100001 }))
        .status,
    ).toBe(409);
    expect(
      (await a.post("/transfers", { recipientId: demoIds.alice, amount: 1 }))
        .status,
    ).toBe(400);
    expect(
      (await a.post("/transfers", { recipientId: randomUUID(), amount: 1 }))
        .status,
    ).toBe(404);
    expect(
      (
        await a.post("/transfers", {
          recipientId: demoIds.bob,
          amount: 1,
          senderId: demoIds.admin,
        })
      ).status,
    ).toBe(400);
    await assertLedger();
  });
  it("transfers atomically with a balanced ledger and owner-only details", async () => {
    const a = await actor();
    const b = await actor("bob");
    const admin = await actor("admin");
    const result = await a.post("/transfers", {
      recipientId: demoIds.bob,
      amount: 70000,
      note: "Lunch",
    });
    expect(result.status).toBe(201);
    const rows = await balances();
    expect(rows[0].balance).toBe("30000");
    expect(rows[1].balance).toBe("170000");
    await assertLedger();
    const path = `/api/v1/transactions/${result.body.transfer.id}`;
    expect((await a.agent.get(path)).status).toBe(200);
    expect((await b.agent.get(path)).status).toBe(200);
    expect((await admin.agent.get(path)).status).toBe(404);
    expect(
      (await a.agent.get("/api/v1/transactions?direction=incoming")).body.items,
    ).toHaveLength(0);
    expect(
      (await b.agent.get("/api/v1/transactions?direction=incoming")).body.items,
    ).toHaveLength(1);
  });
  it("rolls back debit, credit, transfer, and key if ledger writing fails", async () => {
    const a = await actor();
    const before = await balances();
    await pool.query(
      "CREATE FUNCTION reject_test_ledger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test fault'; END $$; CREATE TRIGGER test_fault BEFORE INSERT ON ledger FOR EACH ROW EXECUTE FUNCTION reject_test_ledger()",
    );
    try {
      expect(
        (await a.post("/transfers", { recipientId: demoIds.bob, amount: 100 }))
          .status,
      ).toBe(500);
    } finally {
      await pool.query(
        "DROP TRIGGER test_fault ON ledger; DROP FUNCTION reject_test_ledger()",
      );
    }
    expect(await balances()).toEqual(before);
    expect(
      (await pool.query("SELECT count(*) FROM transfers")).rows[0].count,
    ).toBe("0");
    expect(
      (await pool.query("SELECT count(*) FROM idempotency")).rows[0].count,
    ).toBe("0");
    await assertLedger();
  });
  it("allows exactly one concurrent 70,000 transfer from 100,000; preserves total funds", async () => {
    const a = await actor();
    const blocker = await pool.connect();
    await blocker.query("BEGIN");
    await blocker.query("SELECT id FROM wallets ORDER BY id FOR UPDATE");
    try {
      const p1 = a
        .post("/transfers", { recipientId: demoIds.bob, amount: 70000 })
        .then((r) => r.status);
      const p2 = a
        .post("/transfers", { recipientId: demoIds.bob, amount: 70000 })
        .then((r) => r.status);
      await releaseWhenBlocked(blocker, 2);
      expect((await Promise.all([p1, p2])).sort()).toEqual([201, 409]);
    } finally {
      await blocker.query("ROLLBACK");
      blocker.release();
    }
    const rows = await balances();
    expect(rows[0].balance).toBe("30000");
    expect(rows.reduce((sum, w) => sum + BigInt(w.balance), 0n)).toBe(200000n);
    await assertLedger();
  });
  it("replays repeated keys, rejects changed payloads, and scopes keys to sender", async () => {
    const a = await actor();
    const b = await actor("bob");
    const key = randomUUID();
    const input = { recipientId: demoIds.bob, amount: 500 };
    const first = await a.post("/transfers", input, key);
    const second = await a.post("/transfers", input, key);
    expect(second.status).toBe(200);
    expect(second.body.transfer).toEqual(first.body.transfer);
    expect(
      (await a.post("/transfers", { ...input, amount: 600 }, key)).status,
    ).toBe(409);
    expect(
      (
        await b.post(
          "/transfers",
          { recipientId: demoIds.alice, amount: 500 },
          key,
        )
      ).status,
    ).toBe(201);
    await assertLedger();
  });
  it("coordinates concurrent identical idempotency keys", async () => {
    const a = await actor();
    const key = randomUUID();
    const blocker = await pool.connect();
    await blocker.query("BEGIN");
    await blocker.query("SELECT id FROM wallets ORDER BY id FOR UPDATE");
    try {
      const p1 = a
        .post("/transfers", { recipientId: demoIds.bob, amount: 70000 }, key)
        .then((r) => r);
      const p2 = a
        .post("/transfers", { recipientId: demoIds.bob, amount: 70000 }, key)
        .then((r) => r);
      await releaseWhenBlocked(blocker, 2);
      const results = await Promise.all([p1, p2]);
      expect(results.map((r) => r.status).sort()).toEqual([200, 201]);
      expect(results[0].body.transfer.id).toBe(results[1].body.transfer.id);
    } finally {
      await blocker.query("ROLLBACK");
      blocker.release();
    }
    expect((await balances())[0].balance).toBe("30000");
    expect(
      (await pool.query("SELECT count(*) FROM transfers")).rows[0].count,
    ).toBe("1");
    await assertLedger();
  });
  it("parameterizes search and paginates without exposing unrelated transfers", async () => {
    const a = await actor();
    for (let i = 0; i < 3; i++)
      await a.post("/transfers", {
        recipientId: demoIds.bob,
        amount: 1,
        note: `Item ${i}`,
      });
    const first = await a.agent.get("/api/v1/transactions?limit=2");
    expect(first.body.items).toHaveLength(2);
    expect(first.body.hasMore).toBe(true);
    const second = await a.agent.get("/api/v1/transactions?limit=2&page=2");
    expect(second.body.items).toHaveLength(1);
    const injected = await a.agent
      .get("/api/v1/transactions")
      .query({ search: "' OR 1=1 --" });
    expect(injected.status).toBe(200);
    expect(injected.body.items).toHaveLength(0);
  });
});

describe("SW-09 source and account throttling", () => {
  // The limiters are module-level, so every case uses its own forwarded
  // address and account to get a clean bucket.
  async function attempt(from: string, email: string, csrfAgent = request.agent(app)) {
    const csrf = (await csrfAgent.get("/api/v1/auth/csrf")).body.csrfToken;
    return csrfAgent
      .post("/api/v1/auth/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrf)
      .set("X-Forwarded-For", from)
      .send({ email, password: "wrong-password-entirely" });
  }
  it("gives each forwarded source its own budget instead of one shared bucket", async () => {
    vi.stubEnv("NODE_ENV", "development");
    try {
      let last = 0;
      for (let i = 0; i < 30; i++)
        last = (await attempt("203.0.113.10", `sw09a${i}@example.test`)).status;
      expect(last).toBe(401);
      expect((await attempt("203.0.113.10", "sw09a-final@example.test")).status).toBe(
        429,
      );
      // A different source must not inherit the exhausted budget. Before the
      // fix every request presented as 127.0.0.1 and this returned 429.
      expect((await attempt("203.0.113.11", "sw09b@example.test")).status).toBe(401);
    } finally {
      vi.unstubAllEnvs();
    }
  });
  it("limits guesses against one account even when the source keeps changing", async () => {
    vi.stubEnv("NODE_ENV", "development");
    try {
      const target = "alice@example.test";
      for (let i = 0; i < 10; i++)
        expect((await attempt(`198.51.100.${i}`, target)).status).toBe(401);
      expect((await attempt("198.51.100.200", target)).status).toBe(429);
    } finally {
      vi.unstubAllEnvs();
    }
  });
  it("stores a forged X-Forwarded-For as NULL rather than failing the request", async () => {
    const agent = request.agent(app);
    const csrf = (await agent.get("/api/v1/auth/csrf")).body.csrfToken;
    const result = await agent
      .post("/api/v1/auth/login")
      .set("Origin", origin)
      .set("X-CSRF-Token", csrf)
      .set("X-Forwarded-For", "'; DROP TABLE users; --")
      .send({ email: "bob@example.test", password });
    expect(result.status).toBe(200);
    const row = (
      await pool.query(
        "SELECT source_ip FROM audit_events WHERE event='auth.login' ORDER BY id DESC LIMIT 1",
      )
    ).rows[0];
    expect(row.source_ip).toBeNull();
  });
  it("records failed sign-ins without revealing whether the account exists", async () => {
    const agent = request.agent(app);
    const csrf = (await agent.get("/api/v1/auth/csrf")).body.csrfToken;
    const send = (email: string) =>
      agent
        .post("/api/v1/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .set("X-Forwarded-For", "192.0.2.7")
        .send({ email, password: "wrong-password-entirely" });
    const known = await send("alice@example.test");
    const unknown = await send("nobody@example.test");
    expect(known.status).toBe(401);
    expect(unknown.body).toEqual(known.body);
    const rows = await pool.query(
      "SELECT user_id,host(source_ip) AS ip FROM audit_events WHERE event='auth.login_failed' ORDER BY id",
    );
    expect(rows.rowCount).toBe(2);
    expect(rows.rows[0].user_id).toBe(demoIds.alice);
    expect(rows.rows[1].user_id).toBeNull();
    expect(rows.rows[0].ip).toBe("192.0.2.7");
  });
});

describe("detection rules over the audit trail", () => {
  async function record(event: string, userId: string | null, ip: string | null, times: number) {
    for (let i = 0; i < times; i++)
      await pool.query(
        "INSERT INTO audit_events(user_id,event,source_ip) VALUES($1,$2,$3)",
        [userId, event, ip],
      );
  }
  it("stays silent below the threshold and fires on it", async () => {
    const admin = await actor("admin");
    await record("auth.login_failed", demoIds.alice, "192.0.2.1", 4);
    const quiet = await admin.agent.get("/api/v1/admin/detections");
    expect(quiet.status).toBe(200);
    expect(quiet.body.items.filter((i: { rule: string }) => i.rule === "DET-01")).toHaveLength(0);
    await record("auth.login_failed", demoIds.alice, "192.0.2.1", 1);
    const firing = await admin.agent.get("/api/v1/admin/detections");
    const alert = firing.body.items.find((i: { rule: string }) => i.rule === "DET-01");
    expect(alert).toMatchObject({
      rule: "DET-01",
      severity: "high",
      subject: "alice@example.test",
      count: 5,
      threshold: 5,
    });
    expect(alert.response).toContain("revoke");
  });
  it("separates spraying across accounts from guessing one account", async () => {
    const admin = await actor("admin");
    await record("auth.login_failed", demoIds.alice, "198.51.100.9", 1);
    await record("auth.login_failed", demoIds.bob, "198.51.100.9", 1);
    await record("auth.login_failed", null, "198.51.100.9", 1);
    const result = await admin.agent.get("/api/v1/admin/detections");
    const rules = result.body.items.map((i: { rule: string }) => i.rule);
    expect(rules).toContain("DET-02");
    // No single account reached the DET-01 threshold of five.
    expect(rules).not.toContain("DET-01");
  });
  it("counts denied requests as probing once they cluster", async () => {
    const bob = await actor("bob");
    for (let i = 0; i < 5; i++)
      expect(
        (await bob.agent.get(`/api/v1/tickets/${demoIds.ticket}`)).status,
      ).toBe(404);
    // The denial itself is recorded; the response to Bob is unchanged.
    const admin = await actor("admin");
    const result = await admin.agent.get("/api/v1/admin/detections");
    const alert = result.body.items.find((i: { rule: string }) => i.rule === "DET-05");
    expect(alert).toMatchObject({ subject: "bob@example.test", severity: "medium" });
    expect(alert.count).toBeGreaterThanOrEqual(5);
  });
  it("refuses the detections feed to non-admins and anonymous callers", async () => {
    const bob = await actor("bob");
    expect((await bob.agent.get("/api/v1/admin/detections")).status).toBe(403);
    expect(
      (await request(app).get("/api/v1/admin/detections")).status,
    ).toBe(401);
  });
});

describe("SW-09 follow-on: LIKE metacharacters stay literal", () => {
  it("treats a wildcard-only search as a literal string, not a match-all", async () => {
    const a = await actor();
    await a.post("/transfers", {
      recipientId: demoIds.bob,
      amount: 1,
      note: "Groceries",
    });
    const all = await a.agent.get("/api/v1/transactions");
    expect(all.body.items.length).toBeGreaterThan(0);
    const wildcard = await a.agent.get("/api/v1/transactions").query({ search: "%" });
    expect(wildcard.status).toBe(200);
    expect(wildcard.body.items).toHaveLength(0);
    const underscore = await a.agent.get("/api/v1/transactions").query({ search: "_" });
    expect(underscore.body.items).toHaveLength(0);
    const literal = await a.agent.get("/api/v1/transactions").query({ search: "Groc" });
    expect(literal.body.items).toHaveLength(1);
  });
});

describe("SW-11 control characters in stored text", () => {
  it("rejects a NUL byte with 400 instead of failing inside PostgreSQL", async () => {
    const a = await actor();
    const nul = String.fromCharCode(0);
    const result = await a.post("/tickets", {
      subject: "Support request",
      body: `before${nul}after`,
    });
    expect(result.status).toBe(400);
    expect(result.body.error.code).toBe("VALIDATION_ERROR");
    expect(
      (await pool.query("SELECT count(*) FROM tickets WHERE subject='Support request'"))
        .rows[0].count,
    ).toBe("0");
  });
  it("rejects control characters across every free-text field", async () => {
    const a = await actor();
    const bell = String.fromCharCode(7);
    expect(
      (await a.post("/tickets", { subject: `Sub${bell}`, body: "Body" })).status,
    ).toBe(400);
    expect(
      (
        await a.agent
          .patch("/api/v1/profile")
          .set("Origin", origin)
          .set("X-CSRF-Token", a.csrf)
          .send({ name: `Alice${bell}` })
      ).status,
    ).toBe(400);
    expect(
      (
        await a.post("/transfers", {
          recipientId: demoIds.bob,
          amount: 1,
          note: `Note${bell}`,
        })
      ).status,
    ).toBe(400);
  });
  it("still accepts tab, newline and carriage return in a support message", async () => {
    const a = await actor();
    const body = "First line\nSecond line\twith a tab\r\nThird line";
    const created = await a.post("/tickets", { subject: "Multi-line", body });
    expect(created.status).toBe(201);
    const detail = await a.agent.get(
      `/api/v1/tickets/${created.body.ticket.id}`,
    );
    expect(detail.body.comments[0].body).toContain("Second line");
  });
});
