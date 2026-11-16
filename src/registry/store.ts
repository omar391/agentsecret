import type {
  AccountStatus,
  CustomerAccount,
  CustomerIdentity,
  IdentityInput,
  ProfileInput,
} from "./types";
import { HttpError, now, random } from "../security/primitives";
import type { RegistryDatabase, RegistryResult } from "./database";

interface AccountRow {
  id: string;
  status: string;
  name: string;
  name_token?: string | null;
  email: string | null;
  email_token?: string | null;
  avatar_url: string;
  avatar_token?: string | null;
  version?: number;
  created_at: number;
  updated_at: number;
}

interface IdentityRow {
  id: string;
  account_id: string;
  provider: string;
  provider_subject: string;
  email: string | null;
  email_verified: number;
  profile: string;
  status?: string;
  token?: string | null;
  created_at: number;
  updated_at: number;
}

function mapAccount(row: AccountRow): CustomerAccount {
  return {
    id: row.id,
    status: row.status as AccountStatus,
    name: row.name,
    email: row.email,
    avatarUrl: row.avatar_url,
    version: row.version ?? 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapIdentity(row: IdentityRow): CustomerIdentity {
  let parsedProfile: Record<string, unknown> = {};
  try {
    parsedProfile = JSON.parse(row.profile || "{}");
  } catch {
    parsedProfile = {};
  }
  // The staged-mutation fence token is never part of the published identity shape: only the
  // internal fence read below may observe it.
  return {
    id: row.id,
    accountId: row.account_id,
    provider: row.provider,
    providerSubject: row.provider_subject,
    email: row.email,
    emailVerified: Boolean(row.email_verified),
    profile: parsedProfile,
    status: (row.status as "active" | "pending") || "active",
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function isAccountTombstoned(
  db: RegistryDatabase,
  accountId: string,
): Promise<boolean> {
  try {
    const row = await db
      .prepare(
        "SELECT 1 as present FROM account_tombstones WHERE account_id = ?",
      )
      .bind(accountId)
      .first<{ present: number }>();
    return Boolean(row?.present);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function isIdentityTombstoned(
  db: RegistryDatabase,
  provider: string,
  providerSubject: string,
): Promise<boolean> {
  try {
    const row = await db
      .prepare(
        "SELECT 1 as present FROM identity_tombstones WHERE provider = ? AND provider_subject = ?",
      )
      .bind(provider, providerSubject)
      .first<{ present: number }>();
    return Boolean(row?.present);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function findAccountById(
  db: RegistryDatabase,
  accountId: string,
): Promise<CustomerAccount | null> {
  try {
    const row = await db
      .prepare("SELECT * FROM accounts WHERE id = ?")
      .bind(accountId)
      .first<AccountRow>();
    return row ? mapAccount(row) : null;
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function findIdentity(
  db: RegistryDatabase,
  provider: string,
  providerSubject: string,
  status = "active",
): Promise<CustomerIdentity | null> {
  try {
    const row = await db
      .prepare(
        "SELECT * FROM identities WHERE provider = ? AND provider_subject = ? AND status = ?",
      )
      .bind(provider, providerSubject, status)
      .first<IdentityRow>();
    return row ? mapIdentity(row) : null;
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function findAnyIdentity(
  db: RegistryDatabase,
  provider: string,
  providerSubject: string,
): Promise<CustomerIdentity | null> {
  try {
    const row = await db
      .prepare(
        "SELECT * FROM identities WHERE provider = ? AND provider_subject = ?",
      )
      .bind(provider, providerSubject)
      .first<IdentityRow>();
    return row ? mapIdentity(row) : null;
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

/**
 * Internal read of a staged identity's fence token. This value must never leave the registry as
 * part of a published identity: it is only used to clean up the exact pending row we read.
 */
async function readIdentityFence(
  db: RegistryDatabase,
  provider: string,
  providerSubject: string,
): Promise<{ id: string; token: string } | null> {
  try {
    const row = await db
      .prepare(
        "SELECT id, token FROM identities WHERE provider = ? AND provider_subject = ?",
      )
      .bind(provider, providerSubject)
      .first<{ id: string; token: string | null }>();
    if (!row?.token) return null;
    return { id: row.id, token: row.token };
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function findAccountWithIdentity(
  db: RegistryDatabase,
  provider: string,
  providerSubject: string,
): Promise<{ account: CustomerAccount; identity: CustomerIdentity } | null> {
  const identity = await findIdentity(db, provider, providerSubject, "active");
  if (!identity) return null;
  const account = await findAccountById(db, identity.accountId);
  if (!account) return null;
  return { account, identity };
}

/**
 * Replay of an explicit account id is not a production input: production registration always
 * allocates an opaque `acc_<random>` id, and the only caller that may name an id is recovery.
 * Even then the id is not selectable: it is honored only when this registry already knows it
 * (a live row or a tombstone), so a caller can never mint, alias or predict a tenant id that
 * did not already exist. Unknown ids are rejected as malformed.
 */
const KNOWN_ACCOUNT_ID = /^acc_[A-Za-z0-9_-]{1,64}$/;

export async function createProvisioningAccount(
  db: RegistryDatabase,
  identity: IdentityInput,
  profile?: ProfileInput,
  probeAccountId?: string,
): Promise<{
  account: CustomerAccount;
  identity: CustomerIdentity;
  created: boolean;
}> {
  if (
    await isIdentityTombstoned(db, identity.provider, identity.providerSubject)
  ) {
    throw new HttpError(410, "account_deleted");
  }
  if (probeAccountId !== undefined) {
    if (!KNOWN_ACCOUNT_ID.test(probeAccountId)) {
      throw new HttpError(400, "invalid_account_id");
    }
    const known =
      Boolean(await findAccountById(db, probeAccountId)) ||
      (await isAccountTombstoned(db, probeAccountId));
    if (!known) throw new HttpError(400, "invalid_account_id");
  }
  const overrideAccountId = probeAccountId;
  const accountId = overrideAccountId || "acc_" + random(16);
  if (await isAccountTombstoned(db, accountId)) {
    throw new HttpError(410, "account_deleted");
  }

  const identityId = "ident_" + random(16);
  const timestamp = now();
  const name = profile?.name ?? "";
  const email = identity.emailVerified
    ? identity.email
    : (profile?.email ?? null);
  const avatarUrl = profile?.avatarUrl ?? "";
  const emailVerified = identity.emailVerified ? 1 : 0;
  const profileJson = JSON.stringify(identity.profile ?? {});

  try {
    await db.batch([
      db
        .prepare(
          "INSERT INTO accounts (id, status, name, name_token, email, email_token, avatar_url, avatar_token, version, created_at, updated_at) VALUES (?, 'provisioning', ?, NULL, ?, NULL, ?, NULL, 1, ?, ?)",
        )
        .bind(accountId, name, email, avatarUrl, timestamp, timestamp),
      db
        .prepare(
          "INSERT INTO identities (id, account_id, provider, provider_subject, email, email_verified, profile, status, token, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', NULL, ?, ?)",
        )
        .bind(
          identityId,
          accountId,
          identity.provider,
          identity.providerSubject,
          identity.email ?? null,
          emailVerified,
          profileJson,
          timestamp,
          timestamp,
        ),
    ]);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    const errorStr = String(error?.message || error);
    if (
      errorStr.includes("identity_tombstoned") ||
      errorStr.includes("account_tombstoned")
    ) {
      if (!overrideAccountId) {
        try {
          await db
            .prepare(
              "DELETE FROM accounts WHERE id = ? AND status = 'provisioning'",
            )
            .bind(accountId)
            .run();
        } catch {
          // ignore cleanup error
        }
      }
      throw new HttpError(410, "account_deleted");
    }
    if (
      errorStr.includes("UNIQUE") ||
      errorStr.includes("constraint") ||
      errorStr.includes("identities.provider")
    ) {
      // Clean up the provisional account row if created
      const isAccountCollision =
        Boolean(overrideAccountId) ||
        errorStr.includes("accounts.id") ||
        errorStr.includes("accounts");
      if (!isAccountCollision) {
        try {
          await db
            .prepare(
              "DELETE FROM accounts WHERE id = ? AND status = 'provisioning'",
            )
            .bind(accountId)
            .run();
        } catch {
          // ignore cleanup error
        }
      }
      const existing = await findAccountWithIdentity(
        db,
        identity.provider,
        identity.providerSubject,
      );
      if (existing) return { ...existing, created: false };
      throw new HttpError(409, "identity_conflict");
    }
    throw new HttpError(503, "database_unavailable");
  }

  return {
    account: {
      id: accountId,
      status: "provisioning",
      name,
      email: email ?? null,
      avatarUrl,
      version: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    },
    identity: {
      id: identityId,
      accountId,
      provider: identity.provider,
      providerSubject: identity.providerSubject,
      email: identity.email ?? null,
      emailVerified: Boolean(identity.emailVerified),
      profile: identity.profile ?? {},
      status: "active",
      createdAt: timestamp,
      updatedAt: timestamp,
    },
    created: true,
  };
}

export async function completeAccountActivation(
  db: RegistryDatabase,
  accountId: string,
): Promise<void> {
  if (await isAccountTombstoned(db, accountId)) {
    throw new HttpError(410, "account_deleted");
  }
  const account = await findAccountById(db, accountId);
  if (account?.status === "deleted") {
    throw new HttpError(410, "account_deleted");
  }
  if (!account) {
    throw new HttpError(404, "account_not_found");
  }
  if (account.status === "suspended") {
    throw new HttpError(403, "account_disabled");
  }
  const timestamp = now();
  try {
    const res = await db
      .prepare(
        `UPDATE accounts SET status = 'active', updated_at = ?
         WHERE id = ? AND status = 'provisioning'
           AND NOT EXISTS (SELECT 1 FROM account_tombstones WHERE account_id = ?)`,
      )
      .bind(timestamp, accountId, accountId)
      .run();
    if (!res.meta.changes) {
      if (await isAccountTombstoned(db, accountId)) {
        throw new HttpError(410, "account_deleted");
      }
      const acc = await findAccountById(db, accountId);
      if (acc?.status === "deleted") {
        throw new HttpError(410, "account_deleted");
      }
      if (acc?.status === "suspended") {
        throw new HttpError(403, "account_disabled");
      }
      if (!acc) {
        throw new HttpError(404, "account_not_found");
      }
      if (acc.status === "active") {
        return;
      }
      throw new HttpError(403, "account_disabled");
    }
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function linkIdentity(
  db: RegistryDatabase,
  accountId: string,
  identity: IdentityInput,
  fenceValidator?: () => Promise<void>,
): Promise<CustomerIdentity> {
  if (await isAccountTombstoned(db, accountId)) {
    throw new HttpError(410, "account_deleted");
  }
  if (
    await isIdentityTombstoned(db, identity.provider, identity.providerSubject)
  ) {
    throw new HttpError(410, "account_deleted");
  }
  const account = await findAccountById(db, accountId);
  if (account?.status === "deleted") {
    throw new HttpError(410, "account_deleted");
  }
  if (!account) {
    throw new HttpError(404, "account_not_found");
  }
  if (account.status === "suspended") {
    throw new HttpError(403, "account_disabled");
  }
  if (account.status === "provisioning") {
    throw new HttpError(403, "account_not_activated");
  }

  // 1. Check for committed active identity
  const existing = await findIdentity(
    db,
    identity.provider,
    identity.providerSubject,
    "active",
  );
  if (existing) {
    if (existing.accountId === accountId) return existing;
    throw new HttpError(409, "identity_already_linked");
  }

  // 2. Check for pending uncommitted identity
  const pending = await findAnyIdentity(
    db,
    identity.provider,
    identity.providerSubject,
  );
  if (pending && pending.status === "pending") {
    // Required invariant: ownership/idempotent lookup must not consume an uncommitted identity
    if (now() - pending.createdAt < 3) {
      throw new HttpError(409, "identity_conflict");
    }
    // Stale pending identity from an interrupted/abandoned request: clean up exactly that row.
    const staged = await readIdentityFence(
      db,
      identity.provider,
      identity.providerSubject,
    );
    if (staged && staged.id === pending.id) {
      try {
        await db
          .prepare(
            "DELETE FROM identities WHERE id = ? AND status = 'pending' AND token = ?",
          )
          .bind(staged.id, staged.token)
          .run();
      } catch (cleanupErr: any) {
        if (cleanupErr instanceof HttpError) throw cleanupErr;
        throw new HttpError(503, "database_unavailable");
      }
    }
  }

  // Clean up any stale pending identities for this account (older than 3 seconds)
  await cleanupPendingIdentities(db, 3000, accountId);

  const identityId = "ident_" + random(16);
  const fenceToken = "tok_" + random(16);
  const timestamp = now();
  const emailVerified = identity.emailVerified ? 1 : 0;
  const profileJson = JSON.stringify(identity.profile ?? {});

  try {
    const res = await db
      .prepare(
        `INSERT INTO identities (id, account_id, provider, provider_subject, email, email_verified, profile, status, token, created_at, updated_at)
SELECT ?, id, ?, ?, ?, ?, ?, 'pending', ?, ?, ?
FROM accounts
WHERE id = ? AND status = 'active'`,
      )
      .bind(
        identityId,
        identity.provider,
        identity.providerSubject,
        identity.email ?? null,
        emailVerified,
        profileJson,
        fenceToken,
        timestamp,
        timestamp,
        accountId,
      )
      .run();

    if (!res.meta?.changes) {
      if (
        await isIdentityTombstoned(
          db,
          identity.provider,
          identity.providerSubject,
        )
      ) {
        throw new HttpError(410, "account_deleted");
      }
      if (await isAccountTombstoned(db, accountId)) {
        throw new HttpError(410, "account_deleted");
      }
      const current = await findAccountById(db, accountId);
      if (current?.status === "deleted") {
        throw new HttpError(410, "account_deleted");
      }
      if (!current) {
        throw new HttpError(404, "account_not_found");
      }
      if (current.status === "suspended") {
        throw new HttpError(403, "account_disabled");
      }
      if (current.status === "provisioning") {
        throw new HttpError(403, "account_not_activated");
      }
      throw new HttpError(403, "account_disabled");
    }

    if (fenceValidator) {
      await fenceValidator();
    }

    // Commit identity to 'active' using fenceToken and ensure account remains active
    const commitRes = await db
      .prepare(
        "UPDATE identities SET status = 'active', token = NULL, updated_at = ? WHERE id = ? AND status = 'pending' AND token = ? AND account_id IN (SELECT id FROM accounts WHERE id = ? AND status = 'active')",
      )
      .bind(timestamp, identityId, fenceToken, accountId)
      .run();

    if (!commitRes.meta?.changes || commitRes.meta.changes === 0) {
      if (await isAccountTombstoned(db, accountId)) {
        throw new HttpError(410, "account_deleted");
      }
      const currentAcc = await findAccountById(db, accountId);
      if (currentAcc?.status === "deleted") {
        throw new HttpError(410, "account_deleted");
      }
      if (!currentAcc) {
        throw new HttpError(404, "account_not_found");
      }
      if (currentAcc.status === "suspended") {
        throw new HttpError(403, "account_disabled");
      }
      if (currentAcc.status === "provisioning") {
        throw new HttpError(403, "account_not_activated");
      }
      if (fenceValidator) {
        await fenceValidator();
      }
      throw new HttpError(409, "identity_conflict");
    }

    // The identity is durably published at this point. The account activity timestamp is
    // denormalized metadata that no authorization, idempotency or lookup decision reads, so this
    // maintenance write is best effort: it must never convert a committed publication into a
    // reported failure, because a 503 would invite a retry that collides with its own committed
    // state.
    try {
      await db
        .prepare(
          "UPDATE accounts SET updated_at = ? WHERE id = ? AND status = 'active'",
        )
        .bind(timestamp, accountId)
        .run();
    } catch {
      // Intentionally ignored: the durable identity publication is the authoritative outcome.
    }
  } catch (error: any) {
    try {
      await db
        .prepare(
          "DELETE FROM identities WHERE id = ? AND status = 'pending' AND token = ?",
        )
        .bind(identityId, fenceToken)
        .run();
    } catch {
      // ignore cleanup rollback failure
    }
    if (error instanceof HttpError) throw error;
    const errorStr = String(error?.message || error);
    if (
      errorStr.includes("identity_tombstoned") ||
      errorStr.includes("account_tombstoned")
    ) {
      throw new HttpError(410, "account_deleted");
    }
    if (errorStr.includes("UNIQUE") || errorStr.includes("constraint")) {
      throw new HttpError(409, "identity_already_linked");
    }
    throw new HttpError(503, "database_unavailable");
  }

  return {
    id: identityId,
    accountId,
    provider: identity.provider,
    providerSubject: identity.providerSubject,
    email: identity.email ?? null,
    emailVerified: Boolean(identity.emailVerified),
    profile: identity.profile ?? {},
    status: "active",
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

export async function listIdentities(
  db: RegistryDatabase,
  accountId: string,
): Promise<CustomerIdentity[]> {
  try {
    const { results } = await db
      .prepare(
        "SELECT * FROM identities WHERE account_id = ? AND status = 'active' ORDER BY created_at ASC",
      )
      .bind(accountId)
      .all<IdentityRow>();
    return results.map(mapIdentity);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function cleanupPendingIdentities(
  db: RegistryDatabase,
  olderThanMs = 0,
  accountId?: string,
): Promise<number> {
  try {
    const olderThanSec = Math.max(0, Math.ceil(olderThanMs / 1000));
    const cutoff = now() - olderThanSec;
    let query =
      "DELETE FROM identities WHERE status = 'pending' AND created_at <= ?";
    const bindings: any[] = [cutoff];
    if (accountId) {
      query += " AND account_id = ?";
      bindings.push(accountId);
    }
    const res = await db
      .prepare(query)
      .bind(...bindings)
      .run();
    return res.meta?.changes ?? 0;
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function cleanupPendingProfiles(
  db: RegistryDatabase,
  olderThanMs = 0,
  accountId?: string,
): Promise<number> {
  try {
    const olderThanSec = Math.max(0, Math.ceil(olderThanMs / 1000));
    const cutoff = now() - olderThanSec;
    let query = "DELETE FROM pending_profile_updates WHERE created_at <= ?";
    const bindings: any[] = [cutoff];
    if (accountId) {
      query += " AND account_id = ?";
      bindings.push(accountId);
    }
    const res = await db
      .prepare(query)
      .bind(...bindings)
      .run();
    return res.meta?.changes ?? 0;
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function updateAccountProfile(
  db: RegistryDatabase,
  accountId: string,
  profile: ProfileInput,
  fenceValidator?: () => Promise<void>,
): Promise<CustomerAccount> {
  if (await isAccountTombstoned(db, accountId)) {
    throw new HttpError(410, "account_deleted");
  }

  const existing = await findAccountById(db, accountId);
  if (existing?.status === "deleted") {
    throw new HttpError(410, "account_deleted");
  }
  if (!existing) {
    throw new HttpError(404, "account_not_found");
  }
  if (existing.status === "suspended") {
    throw new HttpError(403, "account_disabled");
  }
  if (existing.status === "provisioning") {
    throw new HttpError(403, "account_not_activated");
  }

  // Clean up any stale pending profile updates (older than 3 seconds)
  await cleanupPendingProfiles(db, 3000, accountId);

  // Stage the update in pending_profile_updates
  const updateId = "prof_" + random(16);
  const token = "tok_" + random(16);
  const timestamp = now();

  try {
    const stageRes = await db
      .prepare(
        `INSERT INTO pending_profile_updates (id, account_id, token, name, email, avatar_url, created_at)
         SELECT ?, id, ?, ?, ?, ?, ?
         FROM accounts
         WHERE id = ? AND status = 'active'`,
      )
      .bind(
        updateId,
        token,
        profile.name ?? null,
        profile.email ?? null,
        profile.avatarUrl ?? null,
        timestamp,
        accountId,
      )
      .run();

    if (!stageRes.meta?.changes || stageRes.meta.changes === 0) {
      if (await isAccountTombstoned(db, accountId)) {
        throw new HttpError(410, "account_deleted");
      }
      const current = await findAccountById(db, accountId);
      if (current?.status === "deleted") {
        throw new HttpError(410, "account_deleted");
      }
      if (!current) {
        throw new HttpError(404, "account_not_found");
      }
      if (current.status === "suspended") {
        throw new HttpError(403, "account_disabled");
      }
      if (current.status === "provisioning") {
        throw new HttpError(403, "account_not_activated");
      }
      throw new HttpError(403, "account_disabled");
    }
  } catch (err: any) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(503, "database_unavailable");
  }

  if (fenceValidator) {
    try {
      await fenceValidator();
    } catch (error) {
      try {
        await db
          .prepare(
            "DELETE FROM pending_profile_updates WHERE id = ? AND token = ?",
          )
          .bind(updateId, token)
          .run();
      } catch (cleanupErr: any) {
        if (cleanupErr instanceof HttpError) throw cleanupErr;
        throw new HttpError(503, "database_unavailable");
      }
      throw error;
    }
  }

  // Commit the staged profile update to accounts
  const sets: string[] = [];
  const bindings: (string | number | null)[] = [];

  if (profile.name !== undefined) {
    sets.push("name = ?");
    bindings.push(profile.name);
  }
  if (profile.email !== undefined) {
    sets.push("email = ?");
    bindings.push(profile.email);
  }
  if (profile.avatarUrl !== undefined) {
    sets.push("avatar_url = ?");
    bindings.push(profile.avatarUrl);
  }

  sets.push("version = version + 1");
  sets.push("updated_at = ?");
  bindings.push(timestamp);

  // The commit is a single D1 batch: the accounts UPDATE and the removal of the staged
  // pending row succeed or fail together. The committed row is returned by that same UPDATE, so
  // the result never depends on a post-commit read that could fail and report a durable update
  // as an error.
  try {
    const results = await db.batch([
      db
        .prepare(
          `UPDATE accounts SET ${sets.join(", ")}
           WHERE id = ? AND status = 'active'
             AND EXISTS (SELECT 1 FROM pending_profile_updates WHERE id = ? AND token = ?)
           RETURNING *`,
        )
        .bind(...bindings, accountId, updateId, token),
      db
        .prepare(
          "DELETE FROM pending_profile_updates WHERE id = ? AND token = ?",
        )
        .bind(updateId, token),
    ]);

    const commitRes = results[0];
    const row = (commitRes?.results?.[0] as AccountRow | undefined) ?? null;
    if (!row || !commitRes?.meta?.changes) {
      // Nothing was committed: diagnostics only, no caller-visible write happened yet.
      if (await isAccountTombstoned(db, accountId)) {
        throw new HttpError(410, "account_deleted");
      }
      const current = await findAccountById(db, accountId);
      if (current?.status === "deleted") {
        throw new HttpError(410, "account_deleted");
      }
      if (!current) {
        throw new HttpError(404, "account_not_found");
      }
      if (current.status === "suspended") {
        throw new HttpError(403, "account_disabled");
      }
      if (current.status === "provisioning") {
        throw new HttpError(403, "account_not_activated");
      }
      if (fenceValidator) {
        await fenceValidator();
      }
      throw new HttpError(409, "profile_conflict");
    }
    return mapAccount(row);
  } catch (err: any) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function markAccountSuspended(
  db: RegistryDatabase,
  accountId: string,
): Promise<void> {
  const timestamp = now();
  let changed = 0;
  try {
    // The status transition and the pending-row cleanup are one atomic batch, and the UPDATE
    // only accepts explicitly permitted source statuses. A tombstoned or already-deleted
    // account can therefore never be resurrected as 'suspended' by a late reconciliation.
    const results = await db.batch([
      db
        .prepare(
          `UPDATE accounts SET status = 'suspended', updated_at = ?
           WHERE id = ? AND status IN ('active', 'provisioning', 'suspended')
             AND NOT EXISTS (SELECT 1 FROM account_tombstones WHERE account_id = ?)`,
        )
        .bind(timestamp, accountId, accountId),
      db
        .prepare(
          `DELETE FROM identities WHERE account_id = ? AND status = 'pending'
             AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND status = 'suspended')`,
        )
        .bind(accountId, accountId),
      db
        .prepare(
          `DELETE FROM pending_profile_updates WHERE account_id = ?
             AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND status = 'suspended')`,
        )
        .bind(accountId, accountId),
    ]);
    changed = Number(results[0]?.meta?.changes || 0);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }

  if (changed > 0) return;

  if (await isAccountTombstoned(db, accountId)) {
    throw new HttpError(410, "account_deleted");
  }
  const account = await findAccountById(db, accountId);
  if (!account) throw new HttpError(404, "account_not_found");
  if (account.status === "deleted") {
    throw new HttpError(410, "account_deleted");
  }
  throw new HttpError(409, "account_conflict");
}

export async function markAccountActive(
  db: RegistryDatabase,
  accountId: string,
): Promise<void> {
  if (await isAccountTombstoned(db, accountId)) {
    throw new HttpError(410, "account_deleted");
  }
  const account = await findAccountById(db, accountId);
  if (account?.status === "deleted") {
    throw new HttpError(410, "account_deleted");
  }
  if (!account) {
    throw new HttpError(404, "account_not_found");
  }
  if (account.status === "suspended") {
    throw new HttpError(403, "account_disabled");
  }
  const timestamp = now();
  try {
    const res = await db
      .prepare(
        `UPDATE accounts SET status = 'active', updated_at = ?
         WHERE id = ? AND status = 'provisioning'
           AND NOT EXISTS (SELECT 1 FROM account_tombstones WHERE account_id = ?)`,
      )
      .bind(timestamp, accountId, accountId)
      .run();
    if (!res.meta.changes) {
      if (await isAccountTombstoned(db, accountId)) {
        throw new HttpError(410, "account_deleted");
      }
      const acc = await findAccountById(db, accountId);
      if (acc?.status === "deleted") {
        throw new HttpError(410, "account_deleted");
      }
      if (acc?.status === "suspended") {
        throw new HttpError(403, "account_disabled");
      }
      if (!acc) {
        throw new HttpError(404, "account_not_found");
      }
      if (acc.status === "active") {
        return;
      }
      throw new HttpError(403, "account_disabled");
    }
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function recordAccountTombstone(
  db: RegistryDatabase,
  accountId: string,
  reason = "deleted",
): Promise<void> {
  const timestamp = now();
  try {
    await db.batch([
      db
        .prepare(
          "INSERT OR REPLACE INTO account_tombstones (account_id, reason, deleted_at) VALUES (?, ?, ?)",
        )
        .bind(accountId, reason, timestamp),
      db
        .prepare(
          "INSERT OR REPLACE INTO identity_tombstones (provider, provider_subject, account_id, deleted_at) SELECT provider, provider_subject, account_id, ? FROM identities WHERE account_id = ?",
        )
        .bind(timestamp, accountId),
      db
        .prepare(
          "UPDATE accounts SET status = 'deleted', updated_at = ? WHERE id = ?",
        )
        .bind(timestamp, accountId),
    ]);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export interface OnboardingState {
  complete: boolean;
  displayName: string | null;
}

const NOT_ONBOARDED: OnboardingState = { complete: false, displayName: null };

/**
 * Read the onboarding state for one account. Absence is a normal answer (the customer has not
 * finished onboarding yet), not an error: a provider sign-up must be usable before it is set.
 */
export async function readOnboarding(
  db: RegistryDatabase,
  accountId: string,
): Promise<OnboardingState> {
  try {
    const row = await db
      .prepare(
        "SELECT display_name FROM account_onboarding WHERE account_id = ?",
      )
      .bind(accountId)
      .first<{ display_name: string }>();
    if (!row) return NOT_ONBOARDED;
    return { complete: true, displayName: row.display_name };
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

/**
 * Record onboarding for one account. Idempotent by construction (`ON CONFLICT` on the primary key),
 * so a repeated submission from a reloaded page converges instead of failing or duplicating.
 */
export async function completeOnboarding(
  db: RegistryDatabase,
  accountId: string,
  displayName: string,
): Promise<OnboardingState> {
  try {
    await db
      .prepare(
        "INSERT INTO account_onboarding (account_id, display_name, completed_at) VALUES (?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET display_name = excluded.display_name, completed_at = excluded.completed_at",
      )
      .bind(accountId, displayName, now())
      .run();
    return { complete: true, displayName };
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export async function deleteAccountRecords(
  db: RegistryDatabase,
  accountId: string,
): Promise<void> {
  const timestamp = now();
  try {
    await db.batch([
      db
        .prepare(
          "INSERT OR IGNORE INTO identity_tombstones (provider, provider_subject, account_id, deleted_at) SELECT provider, provider_subject, account_id, ? FROM identities WHERE account_id = ?",
        )
        .bind(timestamp, accountId),
      db
        .prepare("DELETE FROM pending_profile_updates WHERE account_id = ?")
        .bind(accountId),
      db.prepare("DELETE FROM identities WHERE account_id = ?").bind(accountId),
      db
        .prepare("DELETE FROM account_onboarding WHERE account_id = ?")
        .bind(accountId),
      db.prepare("DELETE FROM accounts WHERE id = ?").bind(accountId),
      db
        .prepare("DELETE FROM deletion_attempts WHERE account_id = ?")
        .bind(accountId),
    ]);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

export type DeletionAttemptPhase = "prepared" | "fenced" | "canceled";

export interface DeletionAttemptRow {
  accountId: string;
  generation: number;
  phase: DeletionAttemptPhase;
}

export interface DeletionFenceResult {
  /** True when the D1 deletion fence for this generation is durably committed. */
  committed: boolean;
  /** Phase/generation of the durable attempt row after the batch (null when absent). */
  phase: DeletionAttemptPhase | null;
  generation: number | null;
}

function mapDeletionAttempt(
  row:
    | {
        account_id: string;
        generation: number;
        phase: string;
      }
    | null
    | undefined,
): DeletionAttemptRow | null {
  if (!row) return null;
  const phase = String(row.phase);
  if (phase !== "prepared" && phase !== "fenced" && phase !== "canceled") {
    throw new HttpError(503, "database_unavailable");
  }
  return {
    accountId: String(row.account_id),
    generation: Number(row.generation),
    phase,
  };
}

export async function readDeletionAttempt(
  db: RegistryDatabase,
  accountId: string,
): Promise<DeletionAttemptRow | null> {
  try {
    const row = await db
      .prepare(
        "SELECT account_id, generation, phase FROM deletion_attempts WHERE account_id = ?",
      )
      .bind(accountId)
      .first<{ account_id: string; generation: number; phase: string }>();
    return mapDeletionAttempt(row);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
}

/**
 * Durably register deletion attempt `generation` and commit the D1 deletion fence in one
 * atomic batch. Registration only succeeds while no fence is committed for this or a newer
 * generation (`prepared`) or a strictly newer attempt supersedes a canceled row. A delayed
 * request for a canceled/superseded attempt can therefore never resurrect a deletion.
 *
 * Registration is restricted to an existing, non-tombstoned account row in the same statement:
 * once the account was tombstoned or purged, a delayed fence (or retry) cannot recreate attempt
 * state for it. The statement is a no-op in that case and the fence update below matches nothing.
 */
export async function fenceDeletionAttempt(
  db: RegistryDatabase,
  accountId: string,
  generation: number,
): Promise<DeletionFenceResult> {
  const timestamp = now();
  let results: RegistryResult<unknown>[];
  try {
    results = await db.batch([
      db
        .prepare(
          `INSERT INTO deletion_attempts (account_id, generation, phase, updated_at)
           SELECT ?, ?, 'prepared', ?
           FROM accounts
           WHERE id = ? AND status != 'deleted'
             AND NOT EXISTS (SELECT 1 FROM account_tombstones WHERE account_id = ?)
           ON CONFLICT(account_id) DO UPDATE SET
             generation = excluded.generation,
             phase = 'prepared',
             updated_at = excluded.updated_at
           WHERE (deletion_attempts.phase = 'prepared'
                  AND deletion_attempts.generation <= excluded.generation)
              OR (deletion_attempts.phase = 'canceled'
                  AND deletion_attempts.generation < excluded.generation)`,
        )
        .bind(accountId, generation, timestamp, accountId, accountId),
      db
        .prepare(
          `UPDATE accounts SET status = 'deleted', updated_at = ?
           WHERE id = ? AND status != 'deleted'
             AND EXISTS (
               SELECT 1 FROM deletion_attempts
               WHERE account_id = ? AND generation = ? AND phase = 'prepared'
             )`,
        )
        .bind(timestamp, accountId, accountId, generation),
      db
        .prepare(
          `UPDATE deletion_attempts SET phase = 'fenced', updated_at = ?
           WHERE account_id = ? AND generation = ? AND phase = 'prepared'
             AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND status = 'deleted')`,
        )
        .bind(timestamp, accountId, generation, accountId),
      db
        .prepare(
          `DELETE FROM pending_profile_updates WHERE account_id = ?
             AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND status = 'deleted')`,
        )
        .bind(accountId, accountId),
      db
        .prepare(
          `DELETE FROM identities WHERE account_id = ? AND status = 'pending'
             AND EXISTS (SELECT 1 FROM accounts WHERE id = ? AND status = 'deleted')`,
        )
        .bind(accountId, accountId),
    ]);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }

  const fenced = Number(results[1]?.meta?.changes || 0) > 0;
  if (fenced) return { committed: true, phase: "fenced", generation };

  // The accounts UPDATE is the commit point. When it changed nothing the attempt row tells
  // whether the fence was already committed by an earlier (retried) identical request.
  const attempt = await readDeletionAttempt(db, accountId);
  return {
    committed: attempt?.phase === "fenced" && attempt.generation === generation,
    phase: attempt?.phase ?? null,
    generation: attempt?.generation ?? null,
  };
}

/**
 * Durably cancel deletion attempt `generation` before any recovery state is released.
 * Once the attempt row is 'canceled' a delayed fence for that generation can never commit.
 * Returns 'fenced' when the D1 fence for this generation is already committed (the caller
 * must then complete cleanup instead of releasing state), 'superseded' when a different
 * generation owns the durable row, and 'absent' when no attempt state exists.
 *
 * The cancel is registered only for an existing, non-tombstoned account and only inserts a row
 * when none exists, so a late cancellation of a purged/tombstoned account is idempotent and
 * never recreates attempt state.
 */
export async function cancelDeletionAttempt(
  db: RegistryDatabase,
  accountId: string,
  generation: number,
): Promise<"canceled" | "fenced" | "superseded" | "absent"> {
  const timestamp = now();
  try {
    await db.batch([
      db
        .prepare(
          `INSERT INTO deletion_attempts (account_id, generation, phase, updated_at)
           SELECT ?, ?, 'canceled', ?
           FROM accounts
           WHERE id = ? AND status != 'deleted'
             AND NOT EXISTS (SELECT 1 FROM account_tombstones WHERE account_id = ?)
           ON CONFLICT(account_id) DO NOTHING`,
        )
        .bind(accountId, generation, timestamp, accountId, accountId),
      db
        .prepare(
          `UPDATE deletion_attempts SET phase = 'canceled', updated_at = ?
           WHERE account_id = ? AND generation = ? AND phase = 'prepared'`,
        )
        .bind(timestamp, accountId, generation),
    ]);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }

  const attempt = await readDeletionAttempt(db, accountId);
  if (!attempt) return "absent";
  if (attempt.phase === "fenced") return "fenced";
  if (attempt.phase === "canceled" && attempt.generation === generation)
    return "canceled";
  return "superseded";
}
