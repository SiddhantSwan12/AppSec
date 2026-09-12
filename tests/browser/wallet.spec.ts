import { test, expect } from "@playwright/test";
test("registration and password reset through the local email catcher", async ({
  page,
  request,
}, testInfo) => {
  const email = `browser-${testInfo.project.name}-${Date.now()}@example.test`;
  const original = "Browser-initial-password!";
  const replacement = "Browser-replacement-password!";
  await page.goto("/register");
  await page.getByLabel("Full name").fill("Browser learner");
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(original);
  await page
    .getByRole("button", { name: "Create account", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Account created");
  await page.goto("/forgot-password");
  await page.getByLabel("Email address").fill(email);
  await page.getByRole("button", { name: "Send reset link" }).click();
  await expect(page.getByRole("status")).toContainText(
    "If that account exists",
  );
  let messageId = "";
  await expect
    .poll(
      async () => {
        const response = await request.get(
          "http://127.0.0.1:8025/api/v1/messages",
        );
        const data = await response.json();
        const message = data.messages.find(
          (m: { ID: string; To: { Address: string }[] }) =>
            m.To.some((to) => to.Address === email),
        );
        messageId = message?.ID ?? "";
        return Boolean(messageId);
      },
      { timeout: 10000 },
    )
    .toBe(true);
  const mail = await (
    await request.get(`http://127.0.0.1:8025/api/v1/message/${messageId}`)
  ).json();
  const resetUrl = String(mail.Text).match(
    /http:\/\/localhost:3000\/reset-password#token=[\w-]+/,
  )?.[0];
  expect(Boolean(resetUrl)).toBe(true);
  await page.goto(resetUrl!);
  await page.getByLabel("New password").fill(replacement);
  await page
    .getByRole("button", { name: "Reset password", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Password reset");
  await page.getByRole("link", { name: "Back to sign in" }).click();
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill(replacement);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator(".balance")).toHaveText("₹0.00");
});
test("login, transfer, history, plain-text support, and logout", async ({
  page,
}, testInfo) => {
  await page.goto("/login");
  await page.getByLabel("Email address").fill("alice@example.test");
  await page
    .getByLabel("Password", { exact: true })
    .fill(process.env.DEMO_PASSWORD!);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Your wallet", exact: true }),
  ).toBeVisible();
  await expect(page.locator(".balance")).toContainText("₹");
  await page.route("**/api/v1/wallet", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: { message: "Wallet temporarily unavailable." },
      }),
    }),
  );
  await page.reload();
  await expect(page.locator(".notice.error")).toContainText(
    "Wallet temporarily unavailable.",
  );
  await expect(page.locator(".balance")).toHaveCount(0);
  await page.unroute("**/api/v1/wallet");
  await page.getByRole("button", { name: "Reload page" }).click();
  await expect(page.locator(".balance")).toContainText("₹");
  await page.screenshot({
    path: `docs/evidence/dashboard-${testInfo.project.name}.png`,
    fullPage: true,
  });
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("link", { name: "Send money" })
    .click();
  await page
    .getByLabel("Recipient account ID")
    .fill("22222222-2222-4222-8222-222222222222");
  await page.getByLabel("Amount in rupees").fill("1.25");
  await page.getByLabel("Note (optional)").fill("Browser verification");
  await page.getByRole("button", { name: "Review transfer" }).click();
  await expect(
    page.getByRole("heading", { name: "Review your transfer" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Confirm transfer" }).click();
  await expect(page.locator(".receipt-amount")).toHaveText("₹1.25");
  await page.getByRole("link", { name: "Back to activity" }).click();
  await expect(page.locator(".activity-list")).toContainText(
    "Browser verification",
  );
  await page
    .getByRole("navigation", { name: "Main navigation" })
    .getByRole("link", { name: "Support", exact: true })
    .click();
  await page
    .getByLabel("Subject", { exact: true })
    .fill(`Browser support ${testInfo.project.name}`);
  const payload =
    "<img src=x onerror=\"document.body.dataset.xss='executed'\">";
  await page.getByLabel("How can we help?").fill(payload);
  await page.getByRole("button", { name: "Send message", exact: true }).click();
  await expect(page.locator(".comment p")).toHaveText(payload);
  expect(await page.locator("body").getAttribute("data-xss")).toBeNull();
  expect(await page.locator(".comment img").count()).toBe(0);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(
    page.getByRole("heading", { name: "Welcome back." }),
  ).toBeVisible();
});
