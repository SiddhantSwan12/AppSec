import { runner } from "node-pg-migrate";
import { fileURLToPath } from "node:url";
import { config } from "./config.js";
export async function migrate(databaseUrl = config.DATABASE_URL) {
  await runner({
    databaseUrl,
    dir: fileURLToPath(new URL("../migrations", import.meta.url)),
    direction: "up",
    migrationsTable: "pgmigrations",
    log: () => {},
  });
}
if (
  process.argv[1]?.endsWith("migrate.ts") ||
  process.argv[1]?.endsWith("migrate.js")
) {
  await migrate();
  console.log("Migrations applied.");
}
