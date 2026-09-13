import express from "express";
import cookieParser from "cookie-parser";
import * as helmetModule from "helmet";
import { z, ZodError } from "zod";
import { randomUUID } from "node:crypto";
import { pool, transaction } from "./db.js";
import { trustProxy } from "./config.js";
import { audit, sourceIp } from "./audit.js";
import { evaluate, rules as detectionRules } from "./detections.js";
import { auth } from "./auth.js";
import {
  ApiError,
  authenticate,
  adminOnly,
  csrfProtection,
} from "./security.js";
import { transfer, transferSchema } from "./transfers.js";
import { safeText } from "./validation.js";

export const app = express();
const helmet = (
  (helmetModule as unknown as { default?: unknown }).default ?? helmetModule
) as () => express.RequestHandler;
app.disable("x-powered-by");
// Without this, every request arrives from the Next.js rewrite as 127.0.0.1 and
// the source-based throttle degrades into one bucket for the whole deployment.
// "loopback" only honours X-Forwarded-For when the TCP peer is local. SW-09.
app.set("trust proxy", trustProxy);
app.use(helmet(), express.json({ limit: "16kb" }), cookieParser());
app.use(
  "/api",
  (_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  },
  csrfProtection,
);
app.get("/api/v1/health", async (_req, res) => {
  await pool.query("SELECT 1");
  res.json({ status: "ok" });
});
app.use("/api/v1/auth", auth);
const api = express.Router();
api.use(authenticate);
const pageSchema = z.object({
  page: z.coerce.number().int().min(1).max(10000).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});
api.get("/wallet", async (req, res) => {
  const wallet = (
    await pool.query(
      "SELECT id,user_id,balance FROM wallets WHERE user_id=$1",
      [req.user!.id],
    )
  ).rows[0];
  res.json({ wallet: { ...wallet, currency: "INR" } });
});
api.patch("/profile", async (req, res) => {
  const input = z
    .object({ name: safeText(80) })
    .strict()
    .parse(req.body);
  const user = (
    await pool.query(
      "UPDATE users SET name=$1 WHERE id=$2 RETURNING id,name,email,role",
      [input.name, req.user!.id],
    )
  ).rows[0];
  res.json({ user });
});
api.post("/transfers", async (req, res) => {
  const input = transferSchema.parse(req.body);
  const key = z
    .string()
    .min(8)
    .max(128)
    .regex(/^[\w-]+$/)
    .parse(req.get("idempotency-key"));
  const result = await transfer(req.user!.id, input, key, sourceIp(req));
  res.status(result.replayed ? 200 : 201).json(result);
});
api.get("/transactions", async (req, res) => {
  const input = pageSchema
    .extend({
      direction: z.enum(["all", "incoming", "outgoing"]).default("all"),
      search: z.string().max(100).default(""),
    })
    .parse(req.query);
  // Parameters keep input out of the SQL structure, but % and _ are still
  // pattern syntax inside LIKE. Escaping them keeps the search a literal
  // substring match instead of a user-controlled scan.
  const like = input.search.replace(/([!%_])/g, "!$1");
  const rows = await pool.query(
    `SELECT t.*,s.name AS sender_name,r.name AS recipient_name FROM transfers t
 JOIN users s ON s.id=t.sender_id JOIN users r ON r.id=t.recipient_id
 WHERE (sender_id=$1 OR recipient_id=$1) AND ($2='all' OR ($2='incoming' AND recipient_id=$1) OR ($2='outgoing' AND sender_id=$1))
 AND (t.note ILIKE '%' || $3 || '%' ESCAPE '!' OR s.name ILIKE '%' || $3 || '%' ESCAPE '!' OR r.name ILIKE '%' || $3 || '%' ESCAPE '!')
 ORDER BY t.created_at DESC,t.id DESC LIMIT $4 OFFSET $5`,
    [
      req.user!.id,
      input.direction,
      like,
      input.limit + 1,
      (input.page - 1) * input.limit,
    ],
  );
  res.json({
    items: rows.rows.slice(0, input.limit),
    page: input.page,
    hasMore: rows.rows.length > input.limit,
  });
});
api.get("/transactions/:id", async (req, res) => {
  const id = z.uuid().parse(req.params.id);
  const row = (
    await pool.query(
      "SELECT * FROM transfers WHERE id=$1 AND (sender_id=$2 OR recipient_id=$2)",
      [id, req.user!.id],
    )
  ).rows[0];
  if (!row) throw new ApiError(404, "NOT_FOUND", "Transaction not found.");
  res.json({ transaction: row });
});
api.get("/tickets", async (req, res) => {
  const { page, limit } = pageSchema.parse(req.query);
  const rows = (
    await pool.query(
      "SELECT * FROM tickets WHERE user_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3",
      [req.user!.id, limit + 1, (page - 1) * limit],
    )
  ).rows;
  res.json({ items: rows.slice(0, limit), page, hasMore: rows.length > limit });
});
api.post("/tickets", async (req, res) => {
  const input = z
    .object({ subject: safeText(120), body: safeText(5000) })
    .strict()
    .parse(req.body);
  const ticket = await transaction(async (db) => {
    const id = randomUUID();
    const row = (
      await db.query(
        "INSERT INTO tickets(id,user_id,subject) VALUES($1,$2,$3) RETURNING *",
        [id, req.user!.id, input.subject],
      )
    ).rows[0];
    await db.query(
      "INSERT INTO comments(id,ticket_id,author_id,body) VALUES($1,$2,$3,$4)",
      [randomUUID(), id, req.user!.id, input.body],
    );
    return row;
  });
  res.status(201).json({ ticket });
});
api.get("/tickets/:id", async (req, res) => {
  const id = z.uuid().parse(req.params.id);
  const ticket = (
    await pool.query(
      "SELECT * FROM tickets WHERE id=$1 AND (user_id=$2 OR $3)",
      [id, req.user!.id, req.user!.role === "admin"],
    )
  ).rows[0];
  if (!ticket)
    throw new ApiError(404, "NOT_FOUND", "Support ticket not found.");
  const comments = (
    await pool.query(
      "SELECT c.id,c.body,c.created_at,u.name,u.role FROM comments c JOIN users u ON u.id=c.author_id WHERE ticket_id=$1 ORDER BY c.created_at,c.id",
      [id],
    )
  ).rows;
  res.json({ ticket, comments });
});
api.post("/tickets/:id/comments", async (req, res) => {
  const id = z.uuid().parse(req.params.id);
  const { body } = z
    .object({ body: safeText(5000) })
    .strict()
    .parse(req.body);
  await transaction(async (db) => {
    const ticket = (
      await db.query(
        "SELECT * FROM tickets WHERE id=$1 AND (user_id=$2 OR $3) FOR UPDATE",
        [id, req.user!.id, req.user!.role === "admin"],
      )
    ).rows[0];
    if (!ticket)
      throw new ApiError(404, "NOT_FOUND", "Support ticket not found.");
    if (ticket.status === "closed")
      throw new ApiError(
        409,
        "TICKET_CLOSED",
        "This ticket is closed. Create a new ticket for more help.",
      );
    await db.query(
      "INSERT INTO comments(id,ticket_id,author_id,body) VALUES($1,$2,$3,$4)",
      [randomUUID(), id, req.user!.id, body],
    );
  });
  res.status(201).json({ message: "Reply added." });
});
api.use("/admin", adminOnly);
// Every admin route also carries the guard directly. The router-level check
// above is the control; repeating it per route means a future refactor that
// moves a handler cannot silently lose it, and it keeps the guard visible to
// the sw-admin-route-missing-role-check Semgrep rule.
// Each entry is a complete literal statement rather than a fragment that gets
// composed at query time. Composing it was safe — the fragment came only from
// this map — but it made every admin list indistinguishable from real SQL
// string building, to a reviewer and to sw-sql-string-interpolation alike. A
// control that cannot be checked mechanically is worth less than the small
// amount of repetition below.
for (const [path, sql] of Object.entries({
  users:
    "SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",
  transactions:
    "SELECT * FROM transfers ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",
  tickets:
    "SELECT * FROM tickets ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",
  "audit-events":
    "SELECT * FROM audit_events ORDER BY created_at DESC,id DESC LIMIT $1 OFFSET $2",
})) {
  api.get(`/admin/${path}`, adminOnly, async (req, res) => {
    const { page, limit } = pageSchema.parse(req.query);
    const rows = (await pool.query(sql, [limit + 1, (page - 1) * limit])).rows;
    res.json({
      items: rows.slice(0, limit),
      page,
      hasMore: rows.length > limit,
    });
  });
}
api.get("/admin/detections", adminOnly, async (_req, res) => {
  res.json({
    generated_at: new Date().toISOString(),
    rules: detectionRules.length,
    items: await evaluate(),
  });
});
api.patch("/admin/tickets/:id", adminOnly, async (req, res) => {
  const id = z.uuid().parse(req.params.id);
  const { status } = z
    .object({ status: z.enum(["open", "closed"]) })
    .strict()
    .parse(req.body);
  const ticket = await transaction(async (db) => {
    const row = (
      await db.query("UPDATE tickets SET status=$1 WHERE id=$2 RETURNING *", [
        status,
        id,
      ])
    ).rows[0];
    if (!row) throw new ApiError(404, "NOT_FOUND", "Support ticket not found.");
    await audit(db, {
      userId: req.user!.id,
      event: "ticket.status_changed",
      resourceId: id,
      ip: sourceIp(req),
    });
    return row;
  });
  res.json({ ticket });
});
app.use("/api/v1", api);
app.use((_req, _res) => {
  throw new ApiError(404, "NOT_FOUND", "Endpoint not found.");
});
const errors: express.ErrorRequestHandler = (error, req, res, _next) => {
  if (error instanceof ZodError) {
    res.status(400).json({
      error: {
        code: "VALIDATION_ERROR",
        message: "Check the fields and try again.",
        fields: error.issues.map((i) => ({
          path: i.path.join("."),
          message: i.message,
        })),
      },
    });
    return;
  }
  if (error instanceof ApiError) {
    // A denial means the control worked. Recording it is what makes a burst of
    // denials visible to DET-05; the response to the caller is unchanged.
    if ((error.status === 403 || error.status === 404) && req.user)
      void audit(pool, {
        userId: req.user.id,
        event: "authz.denied",
        ip: sourceIp(req),
      }).catch(() => {});
    res
      .status(error.status)
      .json({ error: { code: error.code, message: error.message } });
    return;
  }
  if (error?.code === "23505") {
    res.status(409).json({
      error: { code: "CONFLICT", message: "This record already exists." },
    });
    return;
  }
  if (
    error?.type === "entity.parse.failed" ||
    error?.type === "entity.too.large"
  ) {
    res.status(400).json({
      error: {
        code: "INVALID_BODY",
        message: "Send a valid JSON body smaller than 16 KB.",
      },
    });
    return;
  }
  console.error(
    "API request failed:",
    error instanceof Error ? error.name : "unknown",
  );
  res.status(500).json({
    error: {
      code: "INTERNAL_ERROR",
      message: "Something went wrong. Try again later.",
    },
  });
};
app.use(errors);

// Vercel discovers the Express application through this default export.
export default app;
