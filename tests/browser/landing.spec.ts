import { expect, test } from "@playwright/test";

test("landing page is responsive and theme-safe", async ({
  page,
}, testInfo) => {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "A wallet that shows its work." }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Open demo" }).first(),
  ).toBeVisible();
  await expect(
    page.getByAltText("Forest-green wallet object in a softly lit studio"),
  ).toBeVisible();

  const viewport = page.viewportSize();
  const layout = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth,
    viewportWidth: document.documentElement.clientWidth,
    navHeight: document.querySelector(".landing-nav")?.getBoundingClientRect()
      .height,
  }));
  expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
  expect(layout.navHeight).toBeLessThanOrEqual(80);

  if ((viewport?.width ?? 0) >= 1024) {
    const heading = page.locator(".landing-hero h1");
    const lineHeight = Number.parseFloat(
      await heading.evaluate((node) => getComputedStyle(node).lineHeight),
    );
    const height = await heading.evaluate(
      (node) => node.getBoundingClientRect().height,
    );
    expect(height).toBeLessThanOrEqual(lineHeight * 2.1);
  }

  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.reload();
  await expect(page.locator(".landing-page")).toHaveCSS("color-scheme", "dark");
  await page.screenshot({
    path: testInfo.outputPath("landing.png"),
    fullPage: true,
  });
});
