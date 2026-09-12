// Schema-driven API fuzzing with Schemathesis, driven by docs/openapi.json.
//
// The hand-written tests check cases someone thought of. This generates inputs
// from the schema instead, and asserts properties that must hold for every
// endpoint regardless of input: never a 500, never a status the document does
// not declare, never a response that violates its own schema. It is a different
// question from "is this endpoint authorised", which security-runner answers.
//
// Authentication is established first, because an unauthenticated sweep only
// ever proves that everything returns 401.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

const base = process.env.APP_ORIGIN ?? "http://localhost:3000";
const password = process.env.DEMO_PASSWORD;
if (!password) throw new Error("Set DEMO_PASSWORD in .env.");

// Schemathesis ships a console script rather than an executable module, so the
// entry point is invoked directly instead of through `python -m`.
const cli =
  process.platform === "win32"
    ? ".venv/Scripts/schemathesis.exe"
    : ".venv/bin/schemathesis";
if (!existsSync(cli))
  throw new Error(
    "Create .venv and install security-runner/fuzz-requirements.txt first.",
  );

function cookiesFrom(response: Response): string {
  return response.headers
    .getSetCookie()
    .map((cookie) => cookie.split(";")[0])
    .join("; ");
}

const csrfResponse = await fetch(`${base}/api/v1/auth/csrf`);
if (!csrfResponse.ok)
  throw new Error(`Could not reach ${base}. Is the application running?`);
const { csrfToken } = (await csrfResponse.json()) as { csrfToken: string };

const loginResponse = await fetch(`${base}/api/v1/auth/login`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Origin: base,
    "X-CSRF-Token": csrfToken,
    Cookie: cookiesFrom(csrfResponse),
  },
  body: JSON.stringify({ email: "alice@example.test", password }),
});
if (!loginResponse.ok)
  throw new Error(
    `Could not authenticate the seeded demo account (HTTP ${loginResponse.status}). Run npm run db:seed.`,
  );
const session = cookiesFrom(loginResponse);
const { csrfToken: sessionCsrf } = (await loginResponse.json()) as {
  csrfToken: string;
};

// Credential-mutating and session-ending routes are excluded deliberately.
// Fuzzing /auth/logout ends the run's own session; /auth/password and
// /auth/reset-password change the seeded credentials underneath it; and the
// /auth/* routes are throttled by design, so a generated burst would report
// SW-09's own control as a finding.
const excluded = [
  "/auth/logout",
  "/auth/password",
  "/auth/reset-password",
  "/auth/forgot-password",
  "/auth/login",
  "/auth/register",
];

const result = spawnSync(
  cli,
  [
    "run",
    "docs/openapi.json",
    "--url",
    `${base}/api/v1`,
    "--header",
    `Cookie: ${session}`,
    "--header",
    `X-CSRF-Token: ${sessionCsrf}`,
    "--header",
    `Origin: ${base}`,
    "--header",
    "Idempotency-Key: fuzz-run-fixed-key-000001",
    ...excluded.flatMap((path) => ["--exclude-path", path]),
    "--checks",
    // `ignored_auth` and `negative_data_rejection` are deliberately absent.
    // Both work by stripping the documented security scheme and expecting a
    // rejection, but this harness supplies the session as a raw Cookie header,
    // which the stripping cannot remove — so both report "authentication was
    // ignored" for requests that were, in fact, still authenticated. Whether
    // authorisation actually holds is answered properly by security-runner,
    // which drives real anonymous, owner, other-user and admin clients.
    //
    // `unsupported_method` is also absent: it expects 405 for a method that
    // does not exist on a path, and this API returns 404 on purpose, so that a
    // response cannot confirm which paths exist.
    [
      "not_a_server_error",
      "status_code_conformance",
      "content_type_conformance",
      "response_headers_conformance",
      "response_schema_conformance",
      "positive_data_acceptance",
    ].join(","),
    "--max-examples",
    process.env.FUZZ_EXAMPLES ?? "25",
    "--report",
    "junit",
    "--report-junit-path",
    "docs/evidence/fuzz-junit.xml",
  ],
  {
    stdio: "inherit",
    // Schemathesis draws a box-drawing header that the Windows console's
    // default cp1252 encoding cannot represent, which crashes the run before
    // any test executes.
    env: { ...process.env, PYTHONIOENCODING: "utf-8" },
  },
);

if (result.error) throw result.error;
process.exitCode = result.status ?? 2;
