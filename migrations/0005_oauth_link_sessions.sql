-- Binds a linking transaction to the exact customer session that started it.
--
-- `/auth/<provider>?link=1` is started from an authenticated customer session, and
-- `oauth_transactions.link_account_id` records the account the new identity will be linked into.
-- The account alone is not the whole authority: a second session of the same account is a different
-- proof of the same human, so a link pending under a session that has been replaced or revoked must
-- not be completable by the replacement. This table carries the missing half: SHA-256 of the
-- initiating session's opaque cookie value (never the value itself), present only for a linking
-- request. A sign-in has no account authority to bind and has no row here; its browser binding is
-- the transaction's `cookie_hash`.
--
-- The value is compared inside the atomic single-use claim of `oauth_transactions`, not after it, so
-- a callback holding a different session matches no row and therefore cannot spend the transaction
-- it was refused. The row's own `link_account_id` decides which requirement applies, and absence of a
-- row here is never permission: a linked row (`link_account_id IS NOT NULL`) requires a matching row,
-- and a sign-in row (`link_account_id IS NULL`) requires that none exists. A linked row without its
-- row is therefore not claimable at all, which is the state a transaction written before this table
-- existed would be in.
--
-- A companion table rather than a column on `oauth_transactions`: SQLite has no
-- `ADD COLUMN IF NOT EXISTS`, and every migration in this directory must be re-runnable against a
-- database that already carries it - the test harness replays `migrations/` in order against a
-- re-opened persistence directory, exactly as a restarted deployment would. `ALTER TABLE ... ADD
-- COLUMN` fails there with `duplicate column name`, so the whole set has to be idempotent and every
-- other migration here is. `CREATE TABLE IF NOT EXISTS` is.
--
-- No `FOREIGN KEY`: the referenced transaction row is deleted by the expiry sweep, and SQLite only
-- enforces (and cascades) foreign keys when `PRAGMA foreign_keys` is on, which is not the default.
-- The sweep in `createTransaction` removes the rows whose transaction is gone, in the same batch, so
-- the table stays bounded to the transactions that could still be completed.
CREATE TABLE IF NOT EXISTS oauth_link_sessions (
  state_hash TEXT PRIMARY KEY,
  session_hash TEXT NOT NULL
);
