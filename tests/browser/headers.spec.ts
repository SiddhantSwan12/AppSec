import { test, expect } from "@playwright/test";

// SW-10 regression. React escaping is the first control against stored XSS;
// this proves the second layer is actually served, is unique per response, and
// does not break the application it is protecting.
test("serves a nonce-based CSP that the application runs cleanly under", async ({
  page,
}) => {
  const violations: string[] = [];
  page.on("console", (message) => {
    if (
      /content security policy|refused to (load|execute|apply)/i.test(
        message.text(),
      )
    )
      violations.push(message.text());
  });
  page.on("pageerror", (error) => {
    if (/content security policy/i.test(error.message))
      violations.push(error.message);
  });

  const first = await page.goto("/login");
  const policy = first!.headers()["content-security-policy"] ?? "";
  expect(policy).toContain("default-src 'self'");
  expect(policy).toContain("'strict-dynamic'");
  expect(policy).toContain("object-src 'none'");
  expect(policy).toContain("frame-ancestors 'none'");
  expect(policy).toContain("base-uri 'none'");
  // No blanket inline script escape hatch: that would defeat the whole control.
  expect(policy).not.toContain("script-src 'self' 'unsafe-inline'");

  const nonce = policy.match(/'nonce-([^']+)'/)?.[1];
  expect(nonce).toBeTruthy();

  const second = await page.goto("/register");
  const secondPolicy = second!.headers()["content-security-policy"] ?? "";
  const reused = secondPolicy.match(/'nonce-([^']+)'/)?.[1];
  expect(reused).toBeTruthy();
  expect(reused).not.toBe(nonce);

  // The other request-independent headers travel with it.
  const headers = second!.headers();
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["referrer-policy"]).toBe("no-referrer");

  // Navigate through a hydrated client route; nothing may be refused.
  await page.getByRole("link", { name: "Sign in" }).first().click();
  await expect(
    page.getByRole("button", { name: "Sign in", exact: true }),
  ).toBeVisible();
  expect(violations).toEqual([]);
});

test("blocks the inline handler that a stored-XSS payload would rely on", async ({
  page,
}) => {
  await page.goto("/login");
  // `strict-dynamic` deliberately permits scripts created with
  // document.createElement, because a script that already ran is trusted to
  // load its own chunks. The control it provides is over *injected markup*,
  // which is the actual stored-XSS vector in SW-04: an inline event handler
  // needs 'unsafe-inline' in script-src, and this policy never grants it.
  const executed = await page.evaluate(async () => {
    const host = document.createElement("div");
    host.innerHTML =
      '<img src="does-not-exist" onerror="window.__swXss = true">';
    document.body.appendChild(host);
    await new Promise((resolve) => setTimeout(resolve, 400));
    return Boolean((window as unknown as Record<string, unknown>).__swXss);
  });
  expect(executed).toBe(false);
});
