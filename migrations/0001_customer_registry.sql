-- D1 Customer and Identity Registry Migration
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  name_token TEXT,
  email TEXT,
  email_token TEXT,
  avatar_url TEXT NOT NULL DEFAULT '',
  avatar_token TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);

CREATE TABLE IF NOT EXISTS identities (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_subject TEXT NOT NULL,
  email TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  profile TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  token TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(provider, provider_subject)
);

CREATE INDEX IF NOT EXISTS idx_identities_account ON identities(account_id);
CREATE INDEX IF NOT EXISTS idx_identities_provider_subject ON identities(provider, provider_subject);
CREATE INDEX IF NOT EXISTS idx_identities_status ON identities(status);

CREATE TABLE IF NOT EXISTS pending_profile_updates (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token TEXT NOT NULL,
  name TEXT,
  email TEXT,
  avatar_url TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_profile_updates_account ON pending_profile_updates(account_id);

CREATE TABLE IF NOT EXISTS account_tombstones (
  account_id TEXT PRIMARY KEY,
  reason TEXT NOT NULL DEFAULT 'deleted',
  deleted_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_tombstones (
  provider TEXT NOT NULL,
  provider_subject TEXT NOT NULL,
  account_id TEXT NOT NULL,
  deleted_at INTEGER NOT NULL,
  PRIMARY KEY (provider, provider_subject)
);

CREATE INDEX IF NOT EXISTS idx_identity_tombstones_account ON identity_tombstones(account_id);

CREATE TRIGGER IF NOT EXISTS trg_prevent_identity_tombstone_insert
BEFORE INSERT ON identities
FOR EACH ROW
WHEN EXISTS (
  SELECT 1 FROM identity_tombstones
  WHERE provider = NEW.provider AND provider_subject = NEW.provider_subject
)
BEGIN
  SELECT RAISE(ABORT, 'identity_tombstoned');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_identity_tombstone_update
BEFORE UPDATE OF provider, provider_subject ON identities
FOR EACH ROW
WHEN EXISTS (
  SELECT 1 FROM identity_tombstones
  WHERE provider = NEW.provider AND provider_subject = NEW.provider_subject
)
BEGIN
  SELECT RAISE(ABORT, 'identity_tombstoned');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_account_tombstone_insert
BEFORE INSERT ON accounts
FOR EACH ROW
WHEN EXISTS (
  SELECT 1 FROM account_tombstones
  WHERE account_id = NEW.id
)
BEGIN
  SELECT RAISE(ABORT, 'account_tombstoned');
END;
