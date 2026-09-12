// INTENTIONALLY VULNERABLE LAB. This module is never imported by the secure server.
import pg from "pg";
import argon2 from "argon2";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
const value = process.env.LAB_DATABASE_URL;
if (!value) throw new Error("LAB_DATABASE_URL is required.");
const target = new URL(value);
if (
  !["127.0.0.1", "localhost", "[::1]"].includes(target.hostname) ||
  target.pathname !== "/securewallet_lab"
)
  throw new Error(
    "Lab database must be the separate local securewallet_lab database.",
  );
export const labPool = new pg.Pool({ connectionString: value, max: 10 });
export const ids = {
  alice: "11111111-1111-4111-8111-111111111111",
  bob: "22222222-2222-4222-8222-222222222222",
  admin: "33333333-3333-4333-8333-333333333333",
  ticket: "44444444-4444-4444-8444-444444444444",
};
export async function setupLab(reset = false) {
  await labPool.query(`CREATE TABLE IF NOT EXISTS lab_users(id uuid PRIMARY KEY,email text UNIQUE,name text,role text,password_hash text,balance bigint);
 CREATE TABLE IF NOT EXISTS lab_sessions(token_hash text PRIMARY KEY,user_id uuid REFERENCES lab_users(id),expires_at timestamptz);
 CREATE TABLE IF NOT EXISTS lab_tickets(id uuid PRIMARY KEY,user_id uuid,subject text);
 CREATE TABLE IF NOT EXISTS lab_comments(id bigserial PRIMARY KEY,body text);
 CREATE TABLE IF NOT EXISTS lab_transfers(id bigserial PRIMARY KEY,sender_id uuid,recipient_id uuid,amount bigint,note text);`);
  if (reset)
    await labPool.query(
      "TRUNCATE lab_sessions,lab_comments,lab_transfers,lab_tickets,lab_users RESTART IDENTITY CASCADE",
    );
  if (!process.env.DEMO_PASSWORD) throw new Error("DEMO_PASSWORD is required.");
  const hash = await argon2.hash(process.env.DEMO_PASSWORD, {
    type: argon2.argon2id,
  });
  for (const name of ["alice", "bob", "admin"] as const)
    await labPool.query(
      "INSERT INTO lab_users VALUES($1,$2,$3,$4,$5,100000) ON CONFLICT DO NOTHING",
      [
        ids[name],
        `${name}@example.test`,
        name,
        name === "admin" ? "admin" : "user",
        hash,
      ],
    );
  await labPool.query(
    "INSERT INTO lab_tickets VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
    [ids.ticket, ids.alice, "Private Alice support fixture"],
  );
  if (!(await labPool.query("SELECT 1 FROM lab_transfers LIMIT 1")).rowCount)
    await labPool.query(
      "INSERT INTO lab_transfers(sender_id,recipient_id,amount,note) VALUES($1,$2,1,'Private fixture transaction')",
      [ids.bob, ids.admin],
    );
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await setupLab(process.argv.includes("--reset"));
  await labPool.end();
  console.log("Local lab fixtures initialized.");
}
