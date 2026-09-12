exports.up = (pgm) =>
  pgm.sql(`
-- Detection rules group security events by account and by source address, so
-- the address has to be recorded and both access paths need an index.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS source_ip inet;
CREATE INDEX IF NOT EXISTS audit_events_event_time ON audit_events(event, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_user_time ON audit_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_source_time ON audit_events(source_ip, created_at DESC) WHERE source_ip IS NOT NULL;
`);
exports.down = () => {
  throw new Error(
    "Destructive rollback disabled. Reset only the documented local demo database.",
  );
};
