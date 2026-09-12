import { z } from "zod";
export const config = z
  .object({
    DATABASE_URL: z.string().url(),
    APP_ORIGIN: z.string().url().default("http://localhost:3000"),
    PORT: z.coerce.number().default(4000),
    COOKIE_SECURE: z.enum(["true", "false"]).default("false"),
    SMTP_HOST: z.string().default("127.0.0.1"),
    SMTP_PORT: z.coerce.number().default(1025),
    // Express "trust proxy" setting. "loopback" accepts X-Forwarded-For only when
    // the immediate TCP peer is loopback, which is exactly the Next.js rewrite in
    // front of this API. See SW-09 in docs/FINDINGS.md.
    TRUST_PROXY: z.string().default("loopback"),
  })
  .parse(process.env);
if (
  process.env.NODE_ENV === "production" &&
  (config.COOKIE_SECURE !== "true" || !config.APP_ORIGIN.startsWith("https://"))
) {
  throw new Error(
    "Production requires HTTPS APP_ORIGIN and COOKIE_SECURE=true.",
  );
}
if (process.env.NODE_ENV === "production" && config.TRUST_PROXY === "true") {
  // Trusting every hop lets any client forge X-Forwarded-For and defeat
  // source-based throttling. Name the trusted hop count or subnet instead.
  throw new Error(
    'TRUST_PROXY="true" trusts forged X-Forwarded-For headers. Use a hop count, subnet, or "loopback".',
  );
}
export const trustProxy: string | number | boolean =
  config.TRUST_PROXY === "false"
    ? false
    : /^\d+$/.test(config.TRUST_PROXY)
      ? Number(config.TRUST_PROXY)
      : config.TRUST_PROXY;
