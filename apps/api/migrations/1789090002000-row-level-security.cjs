exports.up = (pgm) =>
  pgm.sql(`
-- The Express API supplies these values with transaction-local set_config
-- calls. Empty/missing settings deliberately resolve to NULL/false.
CREATE SCHEMA IF NOT EXISTS securewallet_private;

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securewallet_rls') THEN
    CREATE ROLE securewallet_rls NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOINHERIT NOBYPASSRLS;
  END IF;
END
$role$;
GRANT securewallet_rls TO CURRENT_USER;
GRANT USAGE ON SCHEMA public, securewallet_private TO securewallet_rls;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO securewallet_rls;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO securewallet_rls;

CREATE OR REPLACE FUNCTION securewallet_private.current_user_id()
RETURNS uuid LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION securewallet_private.is_admin()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT COALESCE(current_setting('app.user_role', true) = 'admin', false)
$$;

CREATE OR REPLACE FUNCTION securewallet_private.is_system()
RETURNS boolean LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT COALESCE(current_setting('app.is_system', true) = 'true', false)
$$;

CREATE OR REPLACE FUNCTION securewallet_private.recipient_id()
RETURNS uuid LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('app.recipient_id', true), '')::uuid
$$;

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_select ON users FOR SELECT USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR id = securewallet_private.current_user_id()
  OR EXISTS (
    SELECT 1 FROM transfers t
    WHERE (t.sender_id = securewallet_private.current_user_id()
           OR t.recipient_id = securewallet_private.current_user_id())
      AND (t.sender_id = users.id OR t.recipient_id = users.id)
  )
  OR EXISTS (
    SELECT 1 FROM comments c JOIN tickets t ON t.id = c.ticket_id
    WHERE c.author_id = users.id
      AND t.user_id = securewallet_private.current_user_id()
  )
);
CREATE POLICY users_insert ON users FOR INSERT WITH CHECK (securewallet_private.is_system());
CREATE POLICY users_update ON users FOR UPDATE USING (
  securewallet_private.is_system() OR securewallet_private.is_admin() OR id = securewallet_private.current_user_id()
) WITH CHECK (
  securewallet_private.is_system() OR securewallet_private.is_admin() OR id = securewallet_private.current_user_id()
);
CREATE POLICY users_delete ON users FOR DELETE USING (securewallet_private.is_system());

ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets FORCE ROW LEVEL SECURITY;
CREATE POLICY wallets_select ON wallets FOR SELECT USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR user_id = securewallet_private.current_user_id()
  OR user_id = securewallet_private.recipient_id()
);
CREATE POLICY wallets_insert ON wallets FOR INSERT WITH CHECK (securewallet_private.is_system());
CREATE POLICY wallets_update ON wallets FOR UPDATE USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR user_id = securewallet_private.current_user_id()
  OR user_id = securewallet_private.recipient_id()
) WITH CHECK (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR user_id = securewallet_private.current_user_id()
  OR user_id = securewallet_private.recipient_id()
);
CREATE POLICY wallets_delete ON wallets FOR DELETE USING (securewallet_private.is_system());

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sessions_owner ON sessions USING (
  securewallet_private.is_system() OR user_id = securewallet_private.current_user_id()
) WITH CHECK (
  securewallet_private.is_system() OR user_id = securewallet_private.current_user_id()
);

ALTER TABLE reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE reset_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY reset_tokens_owner ON reset_tokens USING (
  securewallet_private.is_system() OR user_id = securewallet_private.current_user_id()
) WITH CHECK (
  securewallet_private.is_system() OR user_id = securewallet_private.current_user_id()
);

ALTER TABLE transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE transfers FORCE ROW LEVEL SECURITY;
CREATE POLICY transfers_select ON transfers FOR SELECT USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR sender_id = securewallet_private.current_user_id()
  OR recipient_id = securewallet_private.current_user_id()
);
CREATE POLICY transfers_insert ON transfers FOR INSERT WITH CHECK (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR (sender_id = securewallet_private.current_user_id()
      AND recipient_id = securewallet_private.recipient_id())
);
CREATE POLICY transfers_update ON transfers FOR UPDATE USING (securewallet_private.is_system());
CREATE POLICY transfers_delete ON transfers FOR DELETE USING (securewallet_private.is_system());

ALTER TABLE idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency FORCE ROW LEVEL SECURITY;
CREATE POLICY idempotency_owner ON idempotency USING (
  securewallet_private.is_system() OR sender_id = securewallet_private.current_user_id()
) WITH CHECK (
  securewallet_private.is_system() OR sender_id = securewallet_private.current_user_id()
);

ALTER TABLE ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY ledger_select ON ledger FOR SELECT USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR EXISTS (SELECT 1 FROM wallets w WHERE w.id = ledger.wallet_id
             AND w.user_id = securewallet_private.current_user_id())
);
CREATE POLICY ledger_insert ON ledger FOR INSERT WITH CHECK (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR EXISTS (SELECT 1 FROM wallets w WHERE w.id = ledger.wallet_id
             AND (w.user_id = securewallet_private.current_user_id()
                  OR w.user_id = securewallet_private.recipient_id()))
);
CREATE POLICY ledger_update ON ledger FOR UPDATE USING (securewallet_private.is_system());
CREATE POLICY ledger_delete ON ledger FOR DELETE USING (securewallet_private.is_system());

ALTER TABLE tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tickets FORCE ROW LEVEL SECURITY;
CREATE POLICY tickets_select ON tickets FOR SELECT USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR user_id = securewallet_private.current_user_id()
);
CREATE POLICY tickets_insert ON tickets FOR INSERT WITH CHECK (
  securewallet_private.is_system() OR user_id = securewallet_private.current_user_id()
);
CREATE POLICY tickets_update ON tickets FOR UPDATE USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR user_id = securewallet_private.current_user_id()
) WITH CHECK (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR user_id = securewallet_private.current_user_id()
);
CREATE POLICY tickets_delete ON tickets FOR DELETE USING (securewallet_private.is_system());

ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments FORCE ROW LEVEL SECURITY;
CREATE POLICY comments_select ON comments FOR SELECT USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
  OR EXISTS (SELECT 1 FROM tickets t WHERE t.id = comments.ticket_id
             AND t.user_id = securewallet_private.current_user_id())
);
CREATE POLICY comments_insert ON comments FOR INSERT WITH CHECK (
  securewallet_private.is_system()
  OR (author_id = securewallet_private.current_user_id()
      AND EXISTS (SELECT 1 FROM tickets t WHERE t.id = comments.ticket_id
                  AND (t.user_id = securewallet_private.current_user_id()
                       OR securewallet_private.is_admin())))
);
CREATE POLICY comments_update ON comments FOR UPDATE USING (securewallet_private.is_system());
CREATE POLICY comments_delete ON comments FOR DELETE USING (securewallet_private.is_system());

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_select ON audit_events FOR SELECT USING (
  securewallet_private.is_system() OR securewallet_private.is_admin()
);
CREATE POLICY audit_events_insert ON audit_events FOR INSERT WITH CHECK (
  securewallet_private.is_system()
  OR user_id = securewallet_private.current_user_id()
);
CREATE POLICY audit_events_update ON audit_events FOR UPDATE USING (securewallet_private.is_system());
CREATE POLICY audit_events_delete ON audit_events FOR DELETE USING (securewallet_private.is_system());
`);

exports.down = () => {
  throw new Error(
    "Destructive rollback disabled. Reset only the documented local demo database.",
  );
};
