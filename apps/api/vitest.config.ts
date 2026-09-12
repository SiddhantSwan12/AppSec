import { defineConfig } from "vitest/config";
import { loadEnvFile } from "node:process";
loadEnvFile("../../.env");
const testUrl = process.env.TEST_DATABASE_URL;
if (!testUrl || !new URL(testUrl).pathname.endsWith("/securewallet_test"))
  throw new Error("Tests require a separate securewallet_test database.");
process.env.DATABASE_URL = testUrl;
process.env.NODE_ENV = "test";
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    fileParallelism: false,
    testTimeout: 15000,
    hookTimeout: 30000,
    reporters: ["default", "json"],
    outputFile: { json: "../../docs/evidence/api-tests.json" },
  },
});
