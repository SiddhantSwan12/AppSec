import { writeFile } from "node:fs/promises";
const ref = (name) => ({ $ref: `#/components/schemas/${name}` });
const object = (
  properties,
  required = Object.keys(properties),
  additionalProperties = false,
) => ({ type: "object", properties, required, additionalProperties });
const string = { type: "string" };
const uuid = { type: "string", format: "uuid" };
const timestamp = { type: "string", format: "date-time" };
const paise = {
  type: "string",
  pattern: "^-?[0-9]+$",
  description: "Integer paise serialized as a decimal string by PostgreSQL.",
};
const array = (items) => ({ type: "array", items });
// Free text that is stored in PostgreSQL rejects C0 control characters and
// DEL, keeping tab, newline and carriage return. Documenting the constraint
// here is what stops the schema-driven fuzzer generating input the API is
// right to refuse, and keeps docs/openapi.json honest about SW-11.
const controlCodes = [...Array(32).keys()].filter(
  (c) => ![9, 10, 13].includes(c),
);
const escapeCode = (c) => `\\u${c.toString(16).padStart(4, "0")}`;
const noControlCharacters = `^[^${controlCodes.map(escapeCode).join("")}${escapeCode(127)}]*$`;
const freeText = (minLength, maxLength) => ({
  type: "string",
  minLength,
  maxLength,
  pattern: noControlCharacters,
});
const schemas = {
  Error: object({
    error: object(
      {
        code: string,
        message: string,
        fields: array(object({ path: string, message: string })),
      },
      ["code", "message"],
    ),
  }),
  Message: object({ message: string }),
  User: object({
    id: uuid,
    name: string,
    email: { type: "string", format: "email" },
    role: { enum: ["user", "admin"] },
  }),
  AdminUser: object({
    id: uuid,
    name: string,
    email: { type: "string", format: "email" },
    role: { enum: ["user", "admin"] },
    created_at: timestamp,
  }),
  Wallet: object({
    id: uuid,
    user_id: uuid,
    balance: paise,
    currency: { const: "INR" },
  }),
  Transfer: object({
    id: uuid,
    sender_id: uuid,
    recipient_id: uuid,
    amount: paise,
    note: string,
    created_at: timestamp,
  }),
  Activity: object({
    id: uuid,
    sender_id: uuid,
    recipient_id: uuid,
    amount: paise,
    note: string,
    created_at: timestamp,
    sender_name: string,
    recipient_name: string,
  }),
  Ticket: object({
    id: uuid,
    user_id: uuid,
    subject: string,
    status: { enum: ["open", "closed"] },
    created_at: timestamp,
  }),
  Comment: object({
    id: uuid,
    body: string,
    created_at: timestamp,
    name: string,
    role: { enum: ["user", "admin"] },
  }),
  AuditEvent: object({
    id: paise,
    user_id: { type: ["string", "null"], format: "uuid" },
    event: string,
    resource_id: { type: ["string", "null"], format: "uuid" },
    created_at: timestamp,
  }),
  Credentials: object({
    email: { type: "string", format: "email", maxLength: 254 },
    password: { type: "string", minLength: 1, maxLength: 128 },
  }),
  Register: object({
    name: freeText(1, 80),
    email: { type: "string", format: "email", maxLength: 254 },
    password: { type: "string", minLength: 12, maxLength: 128 },
  }),
  TransferInput: object(
    {
      recipientId: uuid,
      amount: { type: "integer", minimum: 1, maximum: 100000000 },
      note: { ...freeText(0, 200), default: "" },
    },
    ["recipientId", "amount"],
  ),
};
const content = (schema) => ({ "application/json": { schema } });
const response = (description, schema) => ({
  description,
  content: content(schema),
});
const page = (name) =>
  object({
    items: array(ref(name)),
    page: { type: "integer" },
    hasMore: { type: "boolean" },
  });
const query = (name, schema) => ({ name, in: "query", schema });
const pagination = [
  query("page", { type: "integer", minimum: 1, maximum: 10000, default: 1 }),
  query("limit", { type: "integer", minimum: 1, maximum: 100, default: 20 }),
];
const id = { name: "id", in: "path", required: true, schema: uuid };
const csrf = [
  {
    name: "Origin",
    in: "header",
    required: true,
    schema: string,
    description: "Must exactly equal APP_ORIGIN.",
  },
  {
    name: "X-CSRF-Token",
    in: "header",
    required: true,
    schema: string,
    description:
      "Value obtained from /auth/csrf, or the rotated value returned by login. Must match the CSRF cookie.",
  },
];
const paths = {};
function endpoint(
  path,
  method,
  summary,
  schema,
  {
    body,
    anonymous = false,
    parameters = [],
    status = 200,
    description = "",
    errors = [400, 401, 403, 404, 409, 429, 500],
  } = {},
) {
  const operation = {
    summary,
    description,
    security: anonymous ? [] : [{ session: [] }],
    parameters: [...parameters, ...(method === "get" ? [] : csrf)],
    responses: { [status]: response("Success", schema) },
  };
  if (body) operation.requestBody = { required: true, content: content(body) };
  for (const code of errors)
    operation.responses[code] = response(
      {
        400: "Invalid input",
        401: "Authentication required or incorrect credentials",
        403: "Role or CSRF rejection",
        404: "Missing or inaccessible resource",
        409: "Conflict or business rule rejection",
        429: "Request limit exceeded",
        500: "Internal error",
      }[code],
      ref("Error"),
    );
  paths[path] ??= {};
  paths[path][method] = operation;
  return operation;
}
endpoint(
  "/health",
  "get",
  "Database health",
  object({ status: { const: "ok" } }),
  { anonymous: true, errors: [500] },
);
endpoint(
  "/auth/csrf",
  "get",
  "Get or reuse CSRF token",
  object({ csrfToken: string }),
  {
    anonymous: true,
    description:
      "Sets a host-only HttpOnly SameSite=Strict CSRF cookie. Call before any state-changing request.",
    errors: [500],
  },
);
endpoint("/auth/register", "post", "Register a normal user", ref("Message"), {
  body: ref("Register"),
  anonymous: true,
  status: 201,
  description:
    "Creates user and zero-balance wallet atomically. Unknown fields, including role, are rejected.",
});
endpoint(
  "/auth/login",
  "post",
  "Create a server-side session",
  object({ user: ref("User"), csrfToken: string }),
  {
    body: ref("Credentials"),
    anonymous: true,
    description:
      "Sets HttpOnly SameSite=Strict session and CSRF cookies. Session expires after 8 hours. The returned CSRF token replaces the previous one.",
  },
);
endpoint(
  "/auth/me",
  "get",
  "Current authenticated user",
  object({ user: ref("User") }),
);
endpoint("/auth/logout", "post", "Invalidate current session", ref("Message"));
endpoint(
  "/auth/password",
  "post",
  "Change password and revoke all sessions",
  ref("Message"),
  {
    body: object({
      currentPassword: { type: "string", maxLength: 128 },
      newPassword: { type: "string", minLength: 12, maxLength: 128 },
    }),
  },
);
endpoint(
  "/auth/forgot-password",
  "post",
  "Request local reset email",
  ref("Message"),
  {
    anonymous: true,
    body: object({
      email: { type: "string", format: "email", maxLength: 254 },
    }),
    description:
      "Always returns the same message. Local Mailpit receives a single-use link that expires in 20 minutes.",
  },
);
endpoint(
  "/auth/reset-password",
  "post",
  "Use reset token once",
  ref("Message"),
  {
    anonymous: true,
    body: object({
      token: { type: "string", pattern: "^[\\w-]{43}$" },
      newPassword: { type: "string", minLength: 12, maxLength: 128 },
    }),
    description: "Revokes all sessions and clears current session cookie.",
  },
);
endpoint(
  "/wallet",
  "get",
  "Current user wallet",
  object({ wallet: ref("Wallet") }),
);
endpoint(
  "/profile",
  "patch",
  "Update own display name",
  object({ user: ref("User") }),
  { body: object({ name: freeText(1, 80) }) },
);
const send = endpoint(
  "/transfers",
  "post",
  "Transfer fake INR atomically",
  object({ transfer: ref("Transfer"), replayed: { type: "boolean" } }),
  {
    status: 201,
    body: ref("TransferInput"),
    parameters: [
      {
        name: "Idempotency-Key",
        in: "header",
        required: true,
        schema: {
          type: "string",
          minLength: 8,
          maxLength: 128,
          pattern: "^[\\w-]+$",
        },
      },
    ],
    description:
      "Sender is derived from session. Locks wallets in deterministic order. Rejects insufficient funds, self transfers, missing recipients and mismatched key reuse. Failed transactions release the key; committed keys have no expiry in this lab project.",
  },
);
send.responses[200] = response(
  "Previously committed result for the same sender, key and normalized payload",
  object({ transfer: ref("Transfer"), replayed: { const: true } }),
);
endpoint(
  "/transactions",
  "get",
  "List own incoming and outgoing transfers",
  page("Activity"),
  {
    parameters: [
      ...pagination,
      query("direction", {
        enum: ["all", "incoming", "outgoing"],
        default: "all",
      }),
      query("search", { type: "string", maxLength: 100, default: "" }),
    ],
  },
);
endpoint(
  "/transactions/{id}",
  "get",
  "Read a transfer involving the caller",
  object({ transaction: ref("Transfer") }),
  {
    parameters: [id],
    description:
      "Admin role does not bypass ownership here. Admins use the dedicated read-only overview.",
  },
);
endpoint("/tickets", "get", "List own support tickets", page("Ticket"), {
  parameters: pagination,
});
endpoint(
  "/tickets",
  "post",
  "Create a support conversation",
  object({ ticket: ref("Ticket") }),
  {
    status: 201,
    body: object({
      subject: freeText(1, 120),
      body: freeText(1, 5000),
    }),
  },
);
endpoint(
  "/tickets/{id}",
  "get",
  "Read owned ticket or administer support",
  object({ ticket: ref("Ticket"), comments: array(ref("Comment")) }),
  { parameters: [id] },
);
endpoint(
  "/tickets/{id}/comments",
  "post",
  "Reply to an open conversation",
  ref("Message"),
  {
    status: 201,
    parameters: [id],
    body: object({ body: freeText(1, 5000) }),
    description:
      "Owner or admin only. Stored as text. Closed tickets reject replies.",
  },
);
for (const [path, name] of Object.entries({
  users: "AdminUser",
  transactions: "Transfer",
  tickets: "Ticket",
  "audit-events": "AuditEvent",
}))
  endpoint(`/admin/${path}`, "get", `Admin-only ${path} overview`, page(name), {
    parameters: pagination,
  });
endpoint(
  "/admin/tickets/{id}",
  "patch",
  "Admin-only support status change",
  object({ ticket: ref("Ticket") }),
  { parameters: [id], body: object({ status: { enum: ["open", "closed"] } }) },
);
await writeFile(
  "docs/openapi.json",
  JSON.stringify(
    {
      openapi: "3.1.0",
      info: {
        title: "SecureWallet secure application",
        version: "0.1.0",
        description:
          "Fake funds only. The intentionally vulnerable lab is excluded. State changes require both strict Origin and CSRF validation. Monetary responses use integer-paise strings.",
      },
      servers: [{ url: "http://localhost:3000/api/v1" }],
      paths,
      components: {
        securitySchemes: {
          session: {
            type: "apiKey",
            in: "cookie",
            name: "sw_session",
            description:
              "Local HTTP cookie. Production HTTPS uses __Host-sw_session, Secure, HttpOnly and SameSite=Strict. Never place it in localStorage.",
          },
        },
        schemas,
      },
    },
    null,
    2,
  ),
);
console.log("OpenAPI specification generated.");
