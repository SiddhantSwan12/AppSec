import { randomUUID } from "node:crypto";
import { z } from "zod";
import { transaction } from "./db.js";
import { ApiError, hashToken } from "./security.js";
import { audit } from "./audit.js";
import { safeOptionalText } from "./validation.js";

export const transferSchema = z
  .object({
    recipientId: z.uuid(),
    amount: z.number().int().positive().max(100000000),
    note: safeOptionalText(200).default(""),
  })
  .strict();
export type TransferInput = z.infer<typeof transferSchema>;
export async function transfer(
  senderId: string,
  input: TransferInput,
  key: string,
  ip: string | null = null,
) {
  if (senderId === input.recipientId)
    throw new ApiError(400, "SELF_TRANSFER", "Choose another account.");
  const fingerprint = hashToken(JSON.stringify(input));
  return transaction(async (db) => {
    // Unique index coordinates identical concurrent keys. A conflicting INSERT
    // waits for the winning transaction; the following SELECT sees its commit.
    const claim = await db.query(
      "INSERT INTO idempotency(sender_id,key,payload_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING key",
      [senderId, key, fingerprint],
    );
    if (!claim.rowCount) {
      const previous = (
        await db.query(
          "SELECT payload_hash,transfer_id FROM idempotency WHERE sender_id=$1 AND key=$2",
          [senderId, key],
        )
      ).rows[0];
      if (previous.payload_hash !== fingerprint)
        throw new ApiError(
          409,
          "IDEMPOTENCY_CONFLICT",
          "This request key was already used for a different transfer.",
        );
      const saved = (
        await db.query("SELECT * FROM transfers WHERE id=$1", [
          previous.transfer_id,
        ])
      ).rows[0];
      if (!saved)
        throw new Error("Committed idempotency record missing transfer");
      return { transfer: saved, replayed: true };
    }
    // The same order on every request prevents A→B / B→A lock inversion.
    const wallets = (
      await db.query(
        "SELECT * FROM wallets WHERE user_id=ANY($1::uuid[]) ORDER BY id FOR UPDATE",
        [[senderId, input.recipientId]],
      )
    ).rows;
    const sender = wallets.find((w) => w.user_id === senderId);
    const recipient = wallets.find((w) => w.user_id === input.recipientId);
    if (!sender || !recipient)
      throw new ApiError(
        404,
        "RECIPIENT_NOT_FOUND",
        "That account could not be found.",
      );
    if (BigInt(sender.balance) < BigInt(input.amount))
      throw new ApiError(
        409,
        "INSUFFICIENT_FUNDS",
        "Your balance is too low for this transfer.",
      );
    if (BigInt(recipient.balance) + BigInt(input.amount) > 9000000000000n)
      throw new ApiError(
        409,
        "BALANCE_LIMIT",
        "The recipient cannot accept this transfer.",
      );
    const id = randomUUID();
    const saved = (
      await db.query(
        "INSERT INTO transfers(id,sender_id,recipient_id,amount,note) VALUES($1,$2,$3,$4,$5) RETURNING *",
        [id, senderId, input.recipientId, input.amount, input.note],
      )
    ).rows[0];
    await db.query("UPDATE wallets SET balance=balance-$1 WHERE id=$2", [
      input.amount,
      sender.id,
    ]);
    await db.query("UPDATE wallets SET balance=balance+$1 WHERE id=$2", [
      input.amount,
      recipient.id,
    ]);
    await db.query(
      "INSERT INTO ledger(wallet_id,transfer_id,amount,kind) VALUES($1,$3,-($4::bigint),'debit'),($2,$3,$4::bigint,'credit')",
      [sender.id, recipient.id, id, input.amount],
    );
    await db.query(
      "UPDATE idempotency SET transfer_id=$1 WHERE sender_id=$2 AND key=$3",
      [id, senderId, key],
    );
    await audit(db, {
      userId: senderId,
      event: "transfer.completed",
      resourceId: id,
      ip,
    });
    return { transfer: saved, replayed: false };
  });
}
