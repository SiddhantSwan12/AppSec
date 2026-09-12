// DO NOT DEPLOY. Every unsafe statement is a deliberately introduced teaching fixture.
import express from "express";
import cookieParser from "cookie-parser";
import { createHash, randomBytes } from "node:crypto";
import argon2 from "argon2";
import { z } from "zod";
import { labPool, setupLab } from "./db.js";
await setupLab();
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "16kb" }), cookieParser());
const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const origin = "http://127.0.0.1:4001";
app.use((req, res, next) => {
  res.set({
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  });
  // Keep the demo script local; scripts may mutate this document but cannot exfiltrate.
  res.set(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'",
  );
  if (
    !["GET", "HEAD", "OPTIONS"].includes(req.method) &&
    (req.get("origin") !== origin ||
      !req.cookies.lab_csrf ||
      req.get("x-csrf-token") !== req.cookies.lab_csrf)
  ) {
    res
      .status(403)
      .json({
        error: { code: "CSRF_REJECTED", message: "Lab CSRF rejected." },
      });
    return;
  }
  next();
});
app.get("/api/v1/health", (_req, res) => res.json({ status: "ok", lab: true }));
app.get("/api/v1/auth/csrf", (_req, res) => {
  const csrfToken = randomBytes(32).toString("base64url");
  res
    .cookie("lab_csrf", csrfToken, {
      httpOnly: true,
      sameSite: "strict",
      path: "/",
    })
    .json({ csrfToken });
});
app.post("/api/v1/auth/login", async (req, res) => {
  const input = z
    .object({ email: z.email(), password: z.string().max(128) })
    .parse(req.body);
  const user = (
    await labPool.query("SELECT * FROM lab_users WHERE email=$1", [input.email])
  ).rows[0];
  if (!user || !(await argon2.verify(user.password_hash, input.password))) {
    res.status(401).json({ error: { message: "Invalid credentials." } });
    return;
  }
  const raw = randomBytes(32).toString("base64url");
  await labPool.query(
    "INSERT INTO lab_sessions VALUES($1,$2,now()+interval '1 hour')",
    [hash(raw), user.id],
  );
  res
    .cookie("lab_session", raw, {
      httpOnly: true,
      sameSite: "strict",
      path: "/",
    })
    .json({ user: { id: user.id, name: user.name, role: user.role } });
});
app.get("/", (_req, res) =>
  res
    .type("html")
    .send(
      '<!doctype html><html lang="en"><title>SecureWallet local lab</title><body><h1>Intentionally vulnerable local lab</h1><p>Fake data only. Run npm run lab:demo from the project directory for reproducible demonstrations.</p><p>These are introduced training flaws, not findings in a real company.</p></body></html>',
    ),
);
app.use(async (req, res, next) => {
  const raw = req.cookies.lab_session;
  const user =
    typeof raw === "string"
      ? (
          await labPool.query(
            "SELECT u.id,u.name,u.email,u.role FROM lab_sessions s JOIN lab_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()",
            [hash(raw)],
          )
        ).rows[0]
      : null;
  if (!user) {
    res.status(401).json({ error: { message: "Sign in to the lab." } });
    return;
  }
  res.locals.user = user;
  next();
});
// BOLA: missing relationship to authenticated user.
app.get("/api/v1/tickets/:id", async (req, res) => {
  const ticket = (
    await labPool.query("SELECT * FROM lab_tickets WHERE id=$1", [
      z.uuid().parse(req.params.id),
    ])
  ).rows[0];
  res.json({ ticket });
});
// BFLA: authentication exists, but the administrator role check is absent.
app.get("/api/v1/admin/users", async (_req, res) =>
  res.json({
    items: (
      await labPool.query(
        "SELECT id,name,email,role FROM lab_users ORDER BY id",
      )
    ).rows,
  }),
);
// SQL injection: unsafe interpolation is deliberately confined to this module.
app.get("/api/v1/transactions", async (req, res) => {
  const search = z
    .string()
    .max(100)
    .parse(req.query.search ?? "");
  const rows = await labPool.query(
    `SELECT * FROM lab_transfers WHERE sender_id='${res.locals.user.id}' AND note ILIKE '%${search}%'`,
  );
  res.json({ items: rows.rows });
});
// Stored XSS: persistent text is deliberately inserted into HTML without escaping.
app.post("/api/v1/comments", async (req, res) => {
  const { body } = z.object({ body: z.string().max(5000) }).parse(req.body);
  await labPool.query("INSERT INTO lab_comments(body) VALUES($1)", [body]);
  res.status(201).json({ message: "Stored." });
});
app.get("/comments", async (_req, res) => {
  const comments = (
    await labPool.query("SELECT body FROM lab_comments ORDER BY id")
  ).rows;
  res
    .type("html")
    .send(
      `<!doctype html><html lang="en"><title>Lab comments</title><body><h1>Unsafe comment rendering</h1>${comments.map((c) => `<article>${c.body}</article>`).join("")}</body></html>`,
    );
});
// Mass assignment: role is incorrectly exposed as a writable field.
app.patch("/api/v1/profile", async (req, res) => {
  const input = z
    .object({
      name: z.string().optional(),
      role: z.enum(["user", "admin"]).optional(),
    })
    .parse(req.body);
  const user = (
    await labPool.query(
      "UPDATE lab_users SET name=COALESCE($1,name),role=COALESCE($2,role) WHERE id=$3 RETURNING id,name,role",
      [input.name, input.role, res.locals.user.id],
    )
  ).rows[0];
  res.json({ user });
});
const arrivals = new Map<
  string,
  {
    resolve: () => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }
>();
async function barrier(group: string) {
  const first = arrivals.get(group);
  if (first) {
    clearTimeout(first.timer);
    arrivals.delete(group);
    first.resolve();
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      arrivals.delete(group);
      reject(new Error("Second race participant missing"));
    }, 8000);
    arrivals.set(group, { resolve, reject, timer });
  });
}
app.get("/api/v1/wallet", async (_req, res) =>
  res.json({
    wallet: (
      await labPool.query(
        "SELECT id AS user_id,balance FROM lab_users WHERE id=$1",
        [res.locals.user.id],
      )
    ).rows[0],
  }),
);
app.post("/api/v1/transfers/:scenario", async (req, res) => {
  const scenario = z
    .enum(["invalid-amount", "race", "retry"])
    .parse(req.params.scenario);
  const input = z
    .object({
      recipientId: z.uuid(),
      amount: z.number().int().min(-100000000).max(100000000),
    })
    .parse(req.body);
  if (input.recipientId === res.locals.user.id) {
    res.status(400).json({ error: { message: "Self transfer rejected." } });
    return;
  }
  if (scenario !== "invalid-amount" && input.amount <= 0) {
    res.status(400).json({ error: { message: "Positive amount required." } });
    return;
  }
  const db = await labPool.connect();
  try {
    if (scenario !== "race") await db.query("BEGIN");
    const rows = (
      await db.query(
        `SELECT id,balance FROM lab_users WHERE id=ANY($1::uuid[]) ORDER BY id ${scenario === "race" ? "" : "FOR UPDATE"}`,
        [[res.locals.user.id, input.recipientId]],
      )
    ).rows;
    const sender = rows.find((r) => r.id === res.locals.user.id);
    const recipient = rows.find((r) => r.id === input.recipientId);
    if (!sender || !recipient || Number(sender.balance) < input.amount) {
      if (scenario !== "race") await db.query("ROLLBACK");
      res.status(409).json({ error: { message: "Transfer rejected." } });
      return;
    }
    // No lock in the race fixture: both requests observe the same pre-debit balance.
    if (scenario === "race")
      await barrier(z.string().min(8).max(64).parse(req.get("x-lab-barrier")));
    await db.query("UPDATE lab_users SET balance=balance-$1 WHERE id=$2", [
      input.amount,
      sender.id,
    ]);
    await db.query("UPDATE lab_users SET balance=balance+$1 WHERE id=$2", [
      input.amount,
      recipient.id,
    ]);
    // The retry fixture ignores Idempotency-Key, so the second request repeats all work.
    const transfer = (
      await db.query(
        "INSERT INTO lab_transfers(sender_id,recipient_id,amount,note) VALUES($1,$2,$3,'Lab demonstration') RETURNING *",
        [sender.id, recipient.id, input.amount],
      )
    ).rows[0];
    if (scenario !== "race") await db.query("COMMIT");
    res.status(201).json({ transfer });
  } catch (error) {
    if (scenario !== "race") await db.query("ROLLBACK");
    throw error;
  } finally {
    db.release();
  }
});
const errors: express.ErrorRequestHandler = (_error, _req, res, _next) =>
  res
    .status(400)
    .json({ error: { message: "Lab request failed. Check scenario inputs." } });
app.use(errors);
const server = app.listen(4001, "127.0.0.1", () =>
  console.log("INTENTIONALLY VULNERABLE local lab: http://127.0.0.1:4001"),
);
for (const signal of ["SIGINT", "SIGTERM"] as const)
  process.on(signal, () =>
    server.close(() => {
      void labPool.end();
    }),
  );
