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
