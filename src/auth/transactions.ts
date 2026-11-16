import { HttpError, now } from "../security/primitives";
import type { RegistryDatabase, RegistryResult } from "../registry/database";
import type { SocialProvider } from "./providers";

/**
 * A pending authorization request, as it is written.
 *
 * Everything the callback must verify and everything the token exchange must send is stored
 * server-side with the `state`, so nothing the browser can choose decides how the exchange is made.
 */
export interface NewTransaction {
  provider: SocialProvider;
  stateHash: string;
  cookieHash: string;
  redirectUri: string;
  codeVerifier: string | null;
  nonce: string | null;
  /**
   * `null` for a sign-in. A linking request carries the account it will link into *and* the session
   * that started it as one value, because they are one authority: the row records the account and
   * `oauth_link_sessions` records the session, and no writer can express one without the other.
   */
  link: { accountId: string; sessionHash: string } | null;
  expiresAt: number;
}

/** A stored authorization request, as `findTransaction` and `claimTransaction` read it back. */
export interface OAuthTransaction extends Omit<NewTransaction, "link"> {
  /**
   * The account a linking request will link into, or `null` for a sign-in. Together with its
   * binding in `oauth_link_sessions` (see migration 0005) this is the initiating authority: the
   * account comes from the row, and the session binding is what proves the callback is the session
   * that asked for the link. `null` does not mean "no requirement one way or the other": it means
   * sign-in, which requires the *absence* of a binding - see `claimTransaction`.
   */
  linkAccountId: string | null;
}

interface TransactionRow {
  state_hash: string;
  provider: string;
  cookie_hash: string;
  code_verifier: string | null;
  nonce: string | null;
  redirect_uri: string;
  link_account_id: string | null;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
}

/** Authorization requests are short-lived: ten minutes is one browser interaction, not a session. */
export const TRANSACTION_TTL_SECONDS = 600;

function mapRow(row: TransactionRow): OAuthTransaction {
  if (row.provider !== "github" && row.provider !== "google")
    throw new HttpError(400, "invalid_state");
  return {
    provider: row.provider,
    stateHash: row.state_hash,
    cookieHash: row.cookie_hash,
    redirectUri: row.redirect_uri,
    codeVerifier: row.code_verifier,
    nonce: row.nonce,
    linkAccountId: row.link_account_id,
    expiresAt: Number(row.expires_at),
  };
}

/**
 * Store a pending authorization request.
 *
 * The account a link is made under and the session that started it arrive as one field, so the row
 * in `oauth_transactions` and its companion row in `oauth_link_sessions` are written together or not
 * at all. That is deliberate: the two halves are one authority, and a writer able to set either
 * alone could create a linked request that no session has to prove. `claimTransaction` refuses such
 * rows anyway, because rows written before migration 0005 predate this shape.
 */
export async function createTransaction(
  db: RegistryDatabase,
  transaction: NewTransaction,
): Promise<void> {
  const timestamp = now();
  const statements = [
    // Expired rows are dropped before the insert, so the table stays bounded to what a browser
    // could still be holding. A pending, unexpired transaction is never removed by this cleanup.
    db
      .prepare("DELETE FROM oauth_transactions WHERE expires_at <= ?")
      .bind(timestamp),
    // Then the session bindings whose transaction is gone with them, in the same batch.
    db.prepare(
      `DELETE FROM oauth_link_sessions
         WHERE NOT EXISTS (SELECT 1 FROM oauth_transactions
                            WHERE oauth_transactions.state_hash = oauth_link_sessions.state_hash)`,
    ),
    db
      .prepare(
        `INSERT INTO oauth_transactions
           (state_hash, provider, cookie_hash, code_verifier, nonce, redirect_uri, link_account_id, created_at, expires_at, consumed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .bind(
        transaction.stateHash,
        transaction.provider,
        transaction.cookieHash,
        transaction.codeVerifier,
        transaction.nonce,
        transaction.redirectUri,
        transaction.link?.accountId ?? null,
        timestamp,
        transaction.expiresAt,
      ),
  ];
  if (transaction.link)
    statements.push(
      db
        .prepare(
          "INSERT INTO oauth_link_sessions (state_hash, session_hash) VALUES (?, ?)",
        )
        .bind(transaction.stateHash, transaction.link.sessionHash),
    );
  try {
    await db.batch(statements);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

/**
 * Read the live transaction this callback would match if its session binding were right. This is a
 * read: it consumes nothing, and the caller never uses it to decide whether a row may be spent.
 * It exists so a refusal that the claim below correctly produces can be reported as the specific
 * refusal it is (`unauthorized`, `session_mismatch`) instead of a bare `invalid_state`.
 */
export async function findTransaction(
  db: RegistryDatabase,
  input: { provider: SocialProvider; stateHash: string; cookieHash: string },
): Promise<OAuthTransaction | null> {
  const timestamp = now();
  let row: TransactionRow | undefined | null;
  try {
    row = await db
      .prepare(
        `SELECT * FROM oauth_transactions
           WHERE state_hash = ? AND provider = ? AND cookie_hash = ?
             AND consumed_at IS NULL AND expires_at > ?`,
      )
      .bind(input.stateHash, input.provider, input.cookieHash, timestamp)
      .first<TransactionRow>();
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
  return row ? mapRow(row) : null;
}

/**
 * Atomically consume the transaction that exactly matches this provider, this `state` hash, this
 * browser cookie hash, its own initiating-session requirement, and has not expired.
 *
 * The single `UPDATE ... RETURNING` is the whole single-use mechanism: SQLite serializes the
 * statement, so of two callbacks presenting the same state exactly one observes `consumed_at IS
 * NULL` and receives the row; the other matches nothing.
 *
 * All of it is in the predicate, so a callback that is refused is refused by matching no row: it
 * cannot spend a transaction it was not entitled to complete. That covers the cookie (`state`
 * without its binding cookie does not consume anything), the provider, and the initiating session.
 *
 * The session half is two opposite requirements, and the row's own `link_account_id` decides which
 * one applies - never the presence or absence of a binding row on its own:
 *   - a linked row requires a binding row for this state whose digest matches the callback's
 *     session, so a sibling session, a replaced session or no session at all matches nothing;
 *   - a sign-in row requires that no binding row exists at all, because a sign-in has no account
 *     authority to prove and a binding beside one means the row's provenance is not what it claims.
 *
 * Absence of a binding row is therefore never read as permission. It is a refusal for a linked row
 * (the case the previous formulation let through: a link started before migration 0005 carried
 * `link_account_id` with no companion row, and was claimable with no session at all) and the
 * requirement for a sign-in row. Both branches are written out rather than inferred from `? IS
 * NULL`, so a `NULL` session hash can only ever satisfy the branch that needs no session.
 */
export async function claimTransaction(
  db: RegistryDatabase,
  input: {
    provider: SocialProvider;
    stateHash: string;
    cookieHash: string;
    sessionHash: string | null;
  },
): Promise<OAuthTransaction | null> {
  const timestamp = now();
  let results: RegistryResult<unknown>[];
  try {
    results = await db.batch([
      db
        .prepare(
          `UPDATE oauth_transactions SET consumed_at = ?
           WHERE state_hash = ? AND provider = ? AND cookie_hash = ?
             AND (
               (link_account_id IS NOT NULL
                AND EXISTS (SELECT 1 FROM oauth_link_sessions
                             WHERE oauth_link_sessions.state_hash = oauth_transactions.state_hash
                               AND oauth_link_sessions.session_hash = ?))
               OR
               (link_account_id IS NULL
                AND NOT EXISTS (SELECT 1 FROM oauth_link_sessions
                                 WHERE oauth_link_sessions.state_hash = oauth_transactions.state_hash))
             )
             AND consumed_at IS NULL AND expires_at > ?
           RETURNING *`,
        )
        .bind(
          timestamp,
          input.stateHash,
          input.provider,
          input.cookieHash,
          input.sessionHash,
          timestamp,
        ),
    ]);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
  const row = results?.[0]?.results?.[0] as TransactionRow | undefined;
  return row ? mapRow(row) : null;
}
