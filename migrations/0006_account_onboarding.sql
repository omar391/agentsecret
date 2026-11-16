-- Customer onboarding state.
--
-- Onboarding is a property of the customer account, not of an email address or a contact
-- verification step: a customer created from a social identity completes it by choosing the
-- display name the account operates under. Verified provider email stays optional metadata on the
-- account and identity rows; nothing here requires one, so a provider that returns no email (or an
-- unverified one) cannot block sign-up, onboarding or approvals.
--
-- The row is an explicit record rather than a derived predicate over `accounts.name`: "has this
-- account been onboarded" must stay answerable even after a profile change, and a derived answer
-- would silently flip when a name is edited. It is keyed by the account and cascades with it, and
-- `deleteAccountRecords` also deletes it explicitly so account deletion never depends on whether
-- the deployment enforces foreign keys.
--
-- Re-runnable: `CREATE TABLE IF NOT EXISTS` is the whole migration, exactly like `0001`-`0005`.
CREATE TABLE IF NOT EXISTS account_onboarding (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL,
  completed_at INTEGER NOT NULL
);
