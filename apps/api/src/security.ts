import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";
import type { RequestHandler } from "express";
import { config } from "./config.js";
import { pool } from "./db.js";

export const hashToken = (token: string) =>
  createHash("sha256").update(token).digest("hex");
export const token = () => randomBytes(32).toString("base64url");
export const hashPassword = (value: string) =>
  argon2.hash(value, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });
export const verifyPassword = (hash: string, value: string) =>
  argon2.verify(hash, value);
export const cookieOptions = {
  httpOnly: true,
  secure: config.COOKIE_SECURE === "true",
  sameSite: "strict" as const,
  path: "/",
};
export const sessionCookie =
  config.COOKIE_SECURE === "true" ? "__Host-sw_session" : "sw_session";
export const csrfCookie =
  config.COOKIE_SECURE === "true" ? "__Host-sw_csrf" : "sw_csrf";
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}
export type Identity = {
  id: string;
  name: string;
  email: string;
  role: "user" | "admin";
};
declare global {
  namespace Express {
    interface Request {
      user?: Identity;
    }
  }
}

export const authenticate: RequestHandler = async (req, res, next) => {
  const raw = req.cookies[sessionCookie];
  if (typeof raw !== "string")
    throw new ApiError(401, "AUTH_REQUIRED", "Please sign in to continue.");
  const result = await pool.query<Identity>(
    `SELECT u.id,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id
 WHERE s.token_hash=$1 AND s.expires_at>now()`,
    [hashToken(raw)],
  );
  if (!result.rows[0])
    throw new ApiError(
      401,
      "AUTH_REQUIRED",
      "Your session has ended. Please sign in again.",
    );
  req.user = result.rows[0];
  next();
};
export const adminOnly: RequestHandler = (req, res, next) => {
  if (req.user?.role !== "admin")
    throw new ApiError(
      403,
      "FORBIDDEN",
      "This page is available to administrators only.",
    );
  next();
};
// Strict Origin validation + a host-only, HttpOnly double-submit CSRF cookie.
// Login/registration are protected too. No CORS is enabled: the web app proxies /api.
export const csrfProtection: RequestHandler = (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const header = req.get("x-csrf-token");
  const cookie = req.cookies[csrfCookie];
  if (
    req.get("origin") !== config.APP_ORIGIN ||
    typeof header !== "string" ||
    typeof cookie !== "string" ||
    Buffer.byteLength(header) !== Buffer.byteLength(cookie) ||
    !timingSafeEqual(Buffer.from(header), Buffer.from(cookie))
  ) {
    throw new ApiError(403, "CSRF_REJECTED", "Refresh the page and try again.");
  }
  next();
};
