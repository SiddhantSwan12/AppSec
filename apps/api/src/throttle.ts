import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import type { Request } from "express";

/**
 * Two limiters guard every authentication route (SW-09).
 *
 * `authSourceThrottle` buckets by client address. It is only meaningful because
 * `app.set("trust proxy", ...)` resolves `req.ip` through the local Next.js
 * rewrite; without it every request presents as 127.0.0.1 and the whole
 * application shares one bucket.
 *
 * `authAccountThrottle` buckets by the account being targeted, so a distributed
 * attacker cannot spread guesses across addresses to stay under the source
 * limit. It skips successful requests, so a legitimate owner signing in never
 * spends the budget that protects them.
 */
const windowMs = 15 * 60 * 1000;
const rejection = (message: string) => ({
  error: { code: "RATE_LIMITED", message },
});
const bypassed = () => process.env.NODE_ENV === "test";

const accountKey = (req: Request): string => {
  if (req.user?.id) return req.user.id;
  const body: unknown = req.body;
  const email =
    typeof body === "object" && body !== null && "email" in body
      ? (body as { email: unknown }).email
      : undefined;
  return typeof email === "string" && email.length <= 254
    ? email.trim().toLowerCase()
    : "";
};

export const authSourceThrottle = rateLimit({
  windowMs,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  skip: bypassed,
  keyGenerator: (req) => `source:${ipKeyGenerator(req.ip ?? "unknown")}`,
  message: rejection("Too many attempts from this network. Try again later."),
});

export const authAccountThrottle = rateLimit({
  windowMs,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  // The key is the targeted account, never an address, so the IPv6 subnet
  // validator does not apply here.
  validate: { ipv6Subnet: false },
  skip: (req) => bypassed() || accountKey(req) === "",
  keyGenerator: (req) => `account:${accountKey(req)}`,
  message: rejection("Too many attempts for this account. Try again later."),
});
