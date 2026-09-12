import { isIP } from "node:net";
import type { Request } from "express";
import type pg from "pg";

export type Queryable = Pick<pg.PoolClient, "query"> | Pick<pg.Pool, "query">;

/**
 * Source addresses are stored as `inet`, so anything that is not a literal IP
 * must become NULL rather than reach PostgreSQL. With `trust proxy` enabled
 * `req.ip` is derived from X-Forwarded-For, which is attacker-influenced text.
 */
export const sourceIp = (req: Request): string | null => {
  const value = req.ip ?? "";
  return isIP(value) ? value : null;
};

export type AuditInput = {
  userId: string | null;
  event: string;
  resourceId?: string | null;
  ip?: string | null;
};

export async function audit(db: Queryable, input: AuditInput): Promise<void> {
  await db.query(
    "INSERT INTO audit_events(user_id,event,resource_id,source_ip) VALUES($1,$2,$3,$4)",
    [input.userId, input.event, input.resourceId ?? null, input.ip ?? null],
  );
}
