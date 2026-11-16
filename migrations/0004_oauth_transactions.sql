-- Short-lived, single-use, browser-bound OAuth transaction records for the customer
-- social sign-in routes (`/auth/github*`, `/auth/google*`).
--
-- One row exists per authorization request that has been issued to a provider and not yet
-- returned. The row carries everything the callback must check and everything the token
-- exchange must send, so that no value the browser can choose decides how the exchange is
-- made:
--
--   state_hash       SHA-256 of the `state` value. The primary key, so a state value is
--                    single-use at the storage layer: `consumed_at` is set by one atomic
--                    `UPDATE ... WHERE consumed_at IS NULL ... RETURNING`, and a second
--                    presentation matches nothing.
--   provider         The provider the state was minted for. A GitHub state presented at the
--                    Google callback matches nothing.
--   cookie_hash      SHA-256 of the independent random value in this browser's transaction
--                    cookie. A state presented without that cookie matches nothing, so a
--                    stolen `state` alone is not a credential.
--   code_verifier    PKCE S256 verifier, minted for every authorization request and sent only in
--                    the server-to-provider token exchange. Both providers support it: GitHub's
--                    authorization-code flow accepts `code_challenge` with
--                    `code_challenge_method=S256`, so there is no provider-specific exception and
--                    no `NULL for GitHub` case. The column is nullable only because a table that
--                    an earlier version of this migration already created is not altered by
--                    `CREATE TABLE IF NOT EXISTS`; every row written now populates it.
--   nonce            OIDC nonce for Google, checked against the `nonce` claim of the returned
--                    id_token. NULL for GitHub, which is not an OIDC provider.
--   redirect_uri     The exact registered callback this transaction started from. The token
--                    exchange uses this stored value, never a value supplied by the callback.
--   link_account_id  Set only when the transaction was started from an authenticated customer
--                    session that asked to link another provider. The callback must present that
--                    same session again, and the new identity is linked to this account instead
--                    of resolving a login.
--
-- `link_account_id` is deliberately not a foreign key: the link is re-authorized at the callback
-- through the live session and the registry's own account checks, so a transaction left behind by
-- a deleted account is inert rather than a second enforcement point that could disagree.
CREATE TABLE IF NOT EXISTS oauth_transactions (
  state_hash TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  cookie_hash TEXT NOT NULL,
  code_verifier TEXT,
  nonce TEXT,
  redirect_uri TEXT NOT NULL,
  link_account_id TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_oauth_transactions_expires ON oauth_transactions(expires_at);
