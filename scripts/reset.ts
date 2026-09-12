import { pool } from "../apps/api/src/db.js";
import { seed } from "../apps/api/src/seed.js";
const url = new URL(process.env.DATABASE_URL!);
if (
  !["localhost", "127.0.0.1"].includes(url.hostname) ||
  url.pathname !== "/securewallet" ||
  !process.argv.includes("--confirm-local-reset")
)
  throw new Error(
    "Reset requires the local securewallet database and --confirm-local-reset. It deletes all local demo records.",
  );
try {
  await pool.query(
    "TRUNCATE audit_events,comments,tickets,ledger,idempotency,transfers,reset_tokens,sessions,wallets,users RESTART IDENTITY CASCADE",
  );
  await seed();
  console.log("Local secure demo data reset.");
} finally {
  await pool.end();
}
