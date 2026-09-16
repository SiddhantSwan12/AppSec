import pg from "pg";
import { config } from "./config.js";
export const pool = new pg.Pool({
  connectionString: config.DATABASE_URL,
  max: 20,
});
// Every query in an atomic operation must use this SAME checked-out connection.
export async function transaction<T>(
  work: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export type DatabaseIdentity = {
  id: string;
  role: "user" | "admin";
};

type RlsContext = {
  identity?: DatabaseIdentity;
  recipientId?: string;
  system?: boolean;
};

async function setRlsContext(
  client: pg.PoolClient,
  context: RlsContext,
): Promise<void> {
  // The deployment connection owns the schema for migrations. Dropping to a
  // NOLOGIN member role makes RLS apply even if that owner has BYPASSRLS.
  await client.query("SET LOCAL ROLE securewallet_rls");
  await client.query(
    `SELECT set_config('app.user_id', $1, true),
            set_config('app.user_role', $2, true),
            set_config('app.recipient_id', $3, true),
            set_config('app.is_system', $4, true)`,
    [
      context.identity?.id ?? "",
      context.identity?.role ?? "",
      context.recipientId ?? "",
      context.system ? "true" : "false",
    ],
  );
}

/** Run application work in a transaction carrying the signed-in identity.
 * PostgreSQL RLS policies read these transaction-local settings. Keeping them
 * local prevents one pooled connection from leaking an identity to another.
 */
export async function withIdentity<T>(
  identity: DatabaseIdentity,
  work: (client: pg.PoolClient) => Promise<T>,
  recipientId?: string,
): Promise<T> {
  return transaction(async (client) => {
    await setRlsContext(client, { identity, recipientId });
    return work(client);
  });
}

/** Restricted escape hatch for unauthenticated account lifecycle operations,
 * seed data, and security telemetry. Never derive this context from a request.
 */
export async function withSystemAccess<T>(
  work: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  return transaction(async (client) => {
    await setRlsContext(client, { system: true });
    return work(client);
  });
}
