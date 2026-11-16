-- Durable generation/phase record for customer account deletion attempts.
-- One row per account, overwritten by later attempts. A fence may only commit while the
-- row is 'prepared' for the requesting generation; 'fenced' is terminal for that generation
-- and 'canceled' blocks a delayed fence from ever committing.
CREATE TABLE IF NOT EXISTS deletion_attempts (
  account_id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL,
  phase TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
