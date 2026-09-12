import { defineConfig, devices } from "@playwright/test";
import { loadEnvFile } from "node:process";
loadEnvFile(".env");
export default defineConfig({
  testDir: "./tests/browser",
  fullyParallel: false,
  workers: 1,
  timeout: 60000,
  reporter: [
    ["list"],
    ["json", { outputFile: "docs/evidence/browser-tests.json" }],
  ],
  use: { baseURL: "http://localhost:3000", trace: "off", screenshot: "off" },
  // SW-09 made authentication throttling per-source rather than global. A
  // browser project drives many sign-ins, so each one presents as its own
  // client instead of sharing a single bucket and starving the other.
  projects: [
    {
      name: "desktop",
      use: {
        ...devices["Desktop Chrome"],
        extraHTTPHeaders: { "X-Forwarded-For": "203.0.113.201" },
      },
    },
    {
      name: "mobile",
      use: {
        ...devices["iPhone 13"],
        defaultBrowserType: "chromium",
        extraHTTPHeaders: { "X-Forwarded-For": "203.0.113.202" },
      },
    },
  ],
  webServer: {
    command: "npm run dev",
    url: "http://localhost:3000/login",
    reuseExistingServer: true,
    timeout: 120000,
  },
});
