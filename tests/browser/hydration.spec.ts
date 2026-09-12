import { test, expect } from "@playwright/test";

// Regression for extension-injected body attributes breaking hydration. Only
// attributes a browser extension could add before React loads are modified, so
// no extension needs to be installed or disabled to reproduce this.
//
// The detector is deliberately positive rather than console-based. Next 16 and
// React 19 no longer surface a hydration mismatch on `console`: an unknown
// extra attribute is accepted silently, and the dev overlay owns what remains.
// A console-only assertion would therefore pass whether or not the application
// hydrated at all. Instead each case proves hydration happened, by setting a
// window marker and requiring it to survive a Link navigation — client-side
// routing preserves it, a full document load would wipe it.
for (const mutation of ["none", "extension-body"] as const) {
  test(`hydration survives ${mutation}`, async ({ page }) => {
    // Known defect, not a regression from the security work: with those
    // attributes present React 19 does not hydrate, so the Link falls back to a
    // full document load. The old console-only assertion passed without ever
    // detecting this. Marked failing so the suite stays honest and flags the
    // day it is fixed. Tracked in docs/PROGRESS.md.
    if (mutation === "extension-body") test.fail();
    const hydrationWarnings: string[] = [];
    page.on("console", (message) => {
      if (/hydrat|server rendered HTML/i.test(message.text()))
        hydrationWarnings.push(message.text());
    });
    page.on("pageerror", (error) => {
      if (/hydrat/i.test(error.message)) hydrationWarnings.push(error.message);
    });
    if (mutation !== "none") {
      await page.route("**/login", async (route) => {
        const response = await route.fetch();
        const html = await response.text();
        expect(html).toContain("<body>");
        const modified = html.replace(
          "<body>",
          '<body data-new-gr-c-s-check-loaded="14.1328.0" data-gr-ext-installed="">',
        );
        expect(modified).not.toBe(html);
        await route.fulfill({ response, body: modified });
      });
    }
    await page.goto("/login");
    await page.evaluate(() => {
      (window as unknown as Record<string, unknown>).__swClientState = "kept";
    });
    // A Link navigation only stays client-side if React actually hydrated.
    await page.getByRole("link", { name: "Forgot password?" }).click();
    await expect(
      page.getByRole("heading", { name: "Let’s get you back in." }),
    ).toBeVisible();
    const survived = await page.evaluate(
      () => (window as unknown as Record<string, unknown>).__swClientState,
    );
    expect(survived).toBe("kept");
    expect(hydrationWarnings).toEqual([]);
  });
}
