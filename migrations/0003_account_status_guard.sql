-- Enforce the closed set of account lifecycle statuses at the schema level.
--
-- Two BEFORE triggers, deliberately not a table rebuild with a CHECK constraint: in SQLite a
-- `accounts` rebuild means writing a new table, copying rows, dropping the original and renaming,
-- which silently drops the anti-resurrection trigger and the indexes defined on `accounts` and
-- invalidates anything that references the table (such as `deletion_attempts.account_id`). Each of
-- those would have to be recreated and re-proved afterwards. Triggers enforce the identical
-- invariant at the same schema level with a far smaller blast radius: no existing object is
-- touched and no window exists in which `accounts` is absent or half-populated.
--
-- The allowed set is the single source of truth for the routing test, which parses this statement
-- (both triggers must agree) instead of hard-coding statuses. A value added here automatically
-- becomes a routing state under test; a value the router does not name is rejected there.
CREATE TRIGGER IF NOT EXISTS trg_prevent_invalid_account_status_insert
BEFORE INSERT ON accounts
FOR EACH ROW
WHEN NEW.status NOT IN ('active', 'provisioning', 'suspended', 'deleted')
BEGIN
  SELECT RAISE(ABORT, 'account_status_invalid');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_invalid_account_status_update
BEFORE UPDATE OF status ON accounts
FOR EACH ROW
WHEN NEW.status NOT IN ('active', 'provisioning', 'suspended', 'deleted')
BEGIN
  SELECT RAISE(ABORT, 'account_status_invalid');
END;
