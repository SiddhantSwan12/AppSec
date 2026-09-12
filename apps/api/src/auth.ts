import { Router, type RequestHandler } from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import nodemailer from "nodemailer";
import { pool, transaction } from "./db.js";
import { config } from "./config.js";
import { audit, sourceIp } from "./audit.js";
import { safeText } from "./validation.js";
import { authAccountThrottle, authSourceThrottle } from "./throttle.js";
import {
  ApiError,
  authenticate,
  cookieOptions,
  csrfCookie,
  sessionCookie,
  hashPassword,
  verifyPassword,
  hashToken,
  token,
} from "./security.js";

export const auth = Router();
const password = z.string().min(12).max(128);
const credentials = z
  .object({
    email: z.email().toLowerCase().max(254),
    password: z.string().min(1).max(128),
  })
  .strict();
const dummyHash = hashPassword("not-a-real-account-password");
const mail = nodemailer.createTransport({
  host: config.SMTP_HOST,
  port: config.SMTP_PORT,
  secure: false,
});
// Every authentication route is guarded by both a source limiter and an
// account limiter. See throttle.ts and SW-09 in docs/FINDINGS.md.
const throttled: [RequestHandler, RequestHandler] = [
  authSourceThrottle,
  authAccountThrottle,
];
auth.get("/csrf", (req, res) => {
  const existing = req.cookies[csrfCookie];
  const value =
    typeof existing === "string" && /^[\w-]{43}$/.test(existing)
      ? existing
      : token();
  res.cookie(csrfCookie, value, cookieOptions).json({ csrfToken: value });
});
auth.post("/register", ...throttled, async (req, res) => {
  const ip = sourceIp(req);
  const input = credentials
    .extend({ name: safeText(80), password })
    .parse(req.body);
  const hash = await hashPassword(input.password);
  await transaction(async (db) => {
    const id = randomUUID();
    // role is absent from the allowlist; PostgreSQL supplies the 'user' default.
    await db.query(
      "INSERT INTO users(id,email,name,password_hash) VALUES($1,$2,$3,$4)",
      [id, input.email, input.name, hash],
    );
    await db.query("INSERT INTO wallets(id,user_id) VALUES($1,$2)", [
      randomUUID(),
      id,
    ]);
    await audit(db, { userId: id, event: "account.registered", ip });
  });
  res.status(201).json({ message: "Account created. You can now sign in." });
});
auth.post("/login", ...throttled, async (req, res) => {
  const ip = sourceIp(req);
  const input = credentials.parse(req.body);
  const raw = token();
  const attempt = await transaction(async (db) => {
    const row = (
      await db.query("SELECT * FROM users WHERE email=$1 FOR UPDATE", [
        input.email,
      ])
    ).rows[0];
    const valid = await verifyPassword(
      row?.password_hash ?? (await dummyHash),
      input.password,
    );
    // A failed attempt must still be recorded, so the failure is reported back
    // rather than thrown: throwing would roll the audit row back with it.
    if (!row || !valid) {
      await audit(db, {
        userId: row?.id ?? null,
        event: "auth.login_failed",
        ip,
      });
      return null;
    }
    await db.query(
      "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '8 hours')",
      [hashToken(raw), row.id],
    );
    await audit(db, { userId: row.id, event: "auth.login", ip });
    return { id: row.id, name: row.name, email: row.email, role: row.role };
  });
  if (!attempt)
    throw new ApiError(
      401,
      "INVALID_CREDENTIALS",
      "Email or password is incorrect.",
    );
  const user = attempt;
  const csrfToken = token();
  res
    .cookie(sessionCookie, raw, {
      ...cookieOptions,
      maxAge: 8 * 60 * 60 * 1000,
    })
    .cookie(csrfCookie, csrfToken, cookieOptions)
    .json({ user, csrfToken });
});
auth.get("/me", authenticate, (req, res) => res.json({ user: req.user }));
auth.post("/logout", authenticate, async (req, res) => {
  await pool.query("DELETE FROM sessions WHERE token_hash=$1", [
    hashToken(req.cookies[sessionCookie]),
  ]);
  await audit(pool, {
    userId: req.user!.id,
    event: "auth.logout",
    ip: sourceIp(req),
  });
  res
    .clearCookie(sessionCookie, cookieOptions)
    .json({ message: "Signed out." });
});
auth.post("/password", authenticate, ...throttled, async (req, res) => {
  const ip = sourceIp(req);
  const input = z
    .object({ currentPassword: z.string().max(128), newPassword: password })
    .strict()
    .parse(req.body);
  const hash = await hashPassword(input.newPassword);
  await transaction(async (db) => {
    const user = (
      await db.query("SELECT password_hash FROM users WHERE id=$1 FOR UPDATE", [
        req.user!.id,
      ])
    ).rows[0];
    if (!(await verifyPassword(user.password_hash, input.currentPassword)))
      throw new ApiError(
        401,
        "INVALID_CREDENTIALS",
        "Current password is incorrect.",
      );
    await db.query("UPDATE users SET password_hash=$1 WHERE id=$2", [
      hash,
      req.user!.id,
    ]);
    await db.query("DELETE FROM sessions WHERE user_id=$1", [req.user!.id]);
    await db.query("DELETE FROM reset_tokens WHERE user_id=$1", [req.user!.id]);
    await audit(db, {
      userId: req.user!.id,
      event: "auth.password_changed",
      ip,
    });
  });
  res
    .clearCookie(sessionCookie, cookieOptions)
    .json({ message: "Password changed. Sign in again." });
});
auth.post("/forgot-password", ...throttled, async (req, res) => {
  const ip = sourceIp(req);
  const { email } = z
    .object({ email: z.email().toLowerCase().max(254) })
    .strict()
    .parse(req.body);
  const raw = token();
  const user = await transaction(async (db) => {
    const row = (
      await db.query("SELECT id,email FROM users WHERE email=$1 FOR UPDATE", [
        email,
      ])
    ).rows[0];
    if (row) {
      await db.query("DELETE FROM reset_tokens WHERE user_id=$1", [row.id]);
      await db.query(
        "INSERT INTO reset_tokens(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '20 minutes')",
        [hashToken(raw), row.id],
      );
    }
    // Recorded for every request, including unknown addresses, so reset abuse
    // is visible to DET-03 without changing the generic public response.
    await audit(db, {
      userId: row?.id ?? null,
      event: "auth.password_reset_requested",
      ip,
    });
    return row;
  });
  if (user) {
    // Fragment avoids putting the reset credential in normal HTTP request logs.
    try {
      await mail.sendMail({
        from: "SecureWallet <support@securewallet.test>",
        to: user.email,
        subject: "Reset your SecureWallet password",
        text: `Reset your password within 20 minutes: ${config.APP_ORIGIN}/reset-password#token=${raw}`,
      });
    } catch {
      console.error("Local reset email delivery failed. Check Mailpit.");
    }
  }
  res.json({ message: "If that account exists, a reset email has been sent." });
});
auth.post("/reset-password", ...throttled, async (req, res) => {
  const ip = sourceIp(req);
  const input = z
    .object({ token: z.string().regex(/^[\w-]{43}$/), newPassword: password })
    .strict()
    .parse(req.body);
  const hash = await hashPassword(input.newPassword);
  await transaction(async (db) => {
    const hint = (
      await db.query("SELECT user_id FROM reset_tokens WHERE token_hash=$1", [
        hashToken(input.token),
      ])
    ).rows[0];
    if (!hint)
      throw new ApiError(
        400,
        "RESET_INVALID",
        "This reset link is invalid or expired. Request a new one.",
      );
    await db.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [
      hint.user_id,
    ]);
    const valid = (
      await db.query(
        "UPDATE reset_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING user_id",
        [hashToken(input.token)],
      )
    ).rows[0];
    if (!valid)
      throw new ApiError(
        400,
        "RESET_INVALID",
        "This reset link is invalid or expired. Request a new one.",
      );
    await db.query("UPDATE users SET password_hash=$1 WHERE id=$2", [
      hash,
      valid.user_id,
    ]);
    await db.query("DELETE FROM sessions WHERE user_id=$1", [valid.user_id]);
    await audit(db, {
      userId: valid.user_id,
      event: "auth.password_reset",
      ip,
    });
  });
  res
    .clearCookie(sessionCookie, cookieOptions)
    .json({ message: "Password reset. Sign in with your new password." });
});
