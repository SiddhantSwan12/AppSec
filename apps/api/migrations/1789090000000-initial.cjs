exports.up = (pgm) =>
  pgm.sql(`
CREATE TABLE users (
 id uuid PRIMARY KEY, email text UNIQUE NOT NULL, name text NOT NULL,
 password_hash text NOT NULL, role text NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE wallets (
 id uuid PRIMARY KEY, user_id uuid UNIQUE NOT NULL REFERENCES users(id),
 balance bigint NOT NULL DEFAULT 0 CHECK (balance BETWEEN 0 AND 9000000000000)
);
CREATE TABLE sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE reset_tokens (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL, used_at timestamptz
);
CREATE TABLE transfers (
 id uuid PRIMARY KEY, sender_id uuid NOT NULL REFERENCES users(id), recipient_id uuid NOT NULL REFERENCES users(id),
 amount bigint NOT NULL CHECK (amount > 0), note text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(), CHECK (sender_id <> recipient_id)
);
CREATE INDEX transfers_sender ON transfers(sender_id,created_at DESC);
CREATE INDEX transfers_recipient ON transfers(recipient_id,created_at DESC);
CREATE TABLE idempotency (
 sender_id uuid NOT NULL REFERENCES users(id), key text NOT NULL, payload_hash text NOT NULL,
 transfer_id uuid REFERENCES transfers(id), PRIMARY KEY(sender_id,key)
);
CREATE TABLE ledger (
 id bigserial PRIMARY KEY, wallet_id uuid NOT NULL REFERENCES wallets(id), transfer_id uuid REFERENCES transfers(id),
 amount bigint NOT NULL CHECK(amount <> 0), kind text NOT NULL CHECK(kind IN ('seed','debit','credit')),
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK ((kind='seed' AND amount>0 AND transfer_id IS NULL) OR
        (kind='debit' AND amount<0 AND transfer_id IS NOT NULL) OR
        (kind='credit' AND amount>0 AND transfer_id IS NOT NULL)),
 UNIQUE(transfer_id,kind)
);
CREATE UNIQUE INDEX one_seed_per_wallet ON ledger(wallet_id) WHERE kind='seed';
CREATE TABLE tickets (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), subject text NOT NULL,
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE comments (
 id uuid PRIMARY KEY, ticket_id uuid NOT NULL REFERENCES tickets(id), author_id uuid NOT NULL REFERENCES users(id),
 body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE audit_events (
 id bigserial PRIMARY KEY, user_id uuid REFERENCES users(id), event text NOT NULL,
 resource_id uuid, created_at timestamptz NOT NULL DEFAULT now()
);
`);
exports.down = () => {
  throw new Error(
    "Destructive rollback disabled. Reset only the documented local demo database.",
  );
};
