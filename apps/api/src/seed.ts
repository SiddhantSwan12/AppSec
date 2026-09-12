import { randomUUID } from "node:crypto";
import { pool, transaction } from "./db.js";
import { hashPassword } from "./security.js";
export const demoIds = {
  alice: "11111111-1111-4111-8111-111111111111",
  bob: "22222222-2222-4222-8222-222222222222",
  admin: "33333333-3333-4333-8333-333333333333",
  ticket: "44444444-4444-4444-8444-444444444444",
};
export async function seed() {
  const password = process.env.DEMO_PASSWORD;
  if (!password || password.length < 12)
    throw new Error("Set DEMO_PASSWORD to at least 12 characters.");
  const hash = await hashPassword(password);
  await transaction(async (db) => {
    for (const name of ["alice", "bob", "admin"] as const) {
      const id = demoIds[name];
      const created = await db.query(
        "INSERT INTO users(id,email,name,password_hash,role) VALUES($1,$2,$3,$4,$5) ON CONFLICT(email) DO NOTHING RETURNING id",
        [
          id,
          `${name}@example.test`,
          name === "admin"
            ? "Demo administrator"
            : name[0].toUpperCase() + name.slice(1),
          hash,
          name === "admin" ? "admin" : "user",
        ],
      );
      if (created.rowCount) {
        const wallet = randomUUID();
        const amount = name === "admin" ? 0 : 100000;
        await db.query(
          "INSERT INTO wallets(id,user_id,balance) VALUES($1,$2,$3)",
          [wallet, id, amount],
        );
        if (amount)
          await db.query(
            "INSERT INTO ledger(wallet_id,amount,kind) VALUES($1,$2,'seed')",
            [wallet, amount],
          );
      }
    }
    await db.query(
      "INSERT INTO tickets(id,user_id,subject) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
      [demoIds.ticket, demoIds.alice, "A question about my demo wallet"],
    );
  });
}
if (
  process.argv[1]?.endsWith("seed.ts") ||
  process.argv[1]?.endsWith("seed.js")
) {
  await seed();
  await pool.end();
  console.log(
    "Demo users and ledger-backed balances seeded. Existing users unchanged.",
  );
}
