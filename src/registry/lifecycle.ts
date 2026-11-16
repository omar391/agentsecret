import type { Env } from "../types";
import type {
  AccountAuthorityState,
  CustomerAccount,
  CustomerIdentity,
  IdentityInput,
  ProfileInput,
} from "./types";
import {
  cancelDeletionAttempt,
  completeAccountActivation,
  createProvisioningAccount,
  deleteAccountRecords,
  fenceDeletionAttempt,
  findAccountById,
  findAccountWithIdentity,
  isAccountTombstoned,
  isIdentityTombstoned,
  linkIdentity,
  markAccountSuspended,
  recordAccountTombstone,
  updateAccountProfile,
  type DeletionFenceResult,
} from "./store";
import { authority } from "../state/authority-kernel";
import { HttpError, now } from "../security/primitives";

export async function registerOrLoginCustomer(
  env: Env,
  input: { identity: IdentityInput; profile?: ProfileInput },
): Promise<{
  account: CustomerAccount;
  identity: CustomerIdentity;
  isNew: boolean;
}> {
  if (!env.DB) throw new HttpError(503, "database_unavailable");

  if (
    await isIdentityTombstoned(
      env.DB,
      input.identity.provider,
      input.identity.providerSubject,
    )
  ) {
    throw new HttpError(410, "account_deleted");
  }

  const existing = await findAccountWithIdentity(
    env.DB,
    input.identity.provider,
    input.identity.providerSubject,
  );

  if (existing) {
    const { account, identity } = existing;
    if (
      account.status === "deleted" ||
      (await isAccountTombstoned(env.DB, account.id))
    ) {
      throw new HttpError(410, "account_deleted");
    }

    const state = await authority<AccountAuthorityState>(env, account.id, {
      op: "get_account_state",
    });
    if (state.tombstoned || state.status === "deleted") {
      await recordAccountTombstone(env.DB, account.id, "authority_deleted");
      throw new HttpError(410, "account_deleted");
    }

    if (state.status === "suspended" || account.status === "suspended") {
      if (state.status === "suspended" && account.status !== "suspended") {
        await markAccountSuspended(env.DB, account.id);
      }
      throw new HttpError(403, "account_disabled");
    }

    if (account.status === "provisioning" || state.status !== "active") {
      // Partial provisioning detected; complete idempotent recovery
      await authority(env, account.id, { op: "activate_account" });
      await completeAccountActivation(env.DB, account.id);
      return {
        account: { ...account, status: "active" },
        identity,
        isNew: false,
      };
    }

    return { account, identity, isNew: false };
  }

  // New registration
  const { account, identity, created } = await createProvisioningAccount(
    env.DB,
    input.identity,
    input.profile,
  );

  if (!created) {
    if (
      account.status === "deleted" ||
      (await isAccountTombstoned(env.DB, account.id))
    ) {
      throw new HttpError(410, "account_deleted");
    }
    const state = await authority<AccountAuthorityState>(env, account.id, {
      op: "get_account_state",
    });
    if (state.tombstoned || state.status === "deleted") {
      await recordAccountTombstone(env.DB, account.id, "authority_deleted");
      throw new HttpError(410, "account_deleted");
    }
    if (state.status === "suspended" || account.status === "suspended") {
      if (state.status === "suspended" && account.status !== "suspended") {
        await markAccountSuspended(env.DB, account.id);
      }
      throw new HttpError(403, "account_disabled");
    }
    if (account.status === "provisioning" || state.status !== "active") {
      await authority(env, account.id, { op: "activate_account" });
      await completeAccountActivation(env.DB, account.id);
      return {
        account: { ...account, status: "active" },
        identity,
        isNew: false,
      };
    }
    return { account, identity, isNew: false };
  }

  try {
    // Activate authority on SQLite Durable Object
    await authority(env, account.id, { op: "activate_account" });
    // Complete D1 activation
    await completeAccountActivation(env.DB, account.id);
    return {
      account: { ...account, status: "active" },
      identity,
      isNew: true,
    };
  } catch (error) {
    // If authority activation or completion failed, leave in provisioning for recovery
    throw error;
  }
}

export async function recoverProvisioningAccount(
  env: Env,
  accountId: string,
): Promise<CustomerAccount> {
  if (!env.DB) throw new HttpError(503, "database_unavailable");
  if (await isAccountTombstoned(env.DB, accountId)) {
    throw new HttpError(410, "account_deleted");
  }

  const account = await findAccountById(env.DB, accountId);
  if (!account) throw new HttpError(404, "account_not_found");
  if (account.status === "deleted") {
    throw new HttpError(410, "account_deleted");
  }
  if (account.status === "suspended") {
    throw new HttpError(403, "account_disabled");
  }

  const state = await authority<AccountAuthorityState>(env, accountId, {
    op: "get_account_state",
  });
  if (state.tombstoned || state.status === "deleted") {
    await recordAccountTombstone(env.DB, accountId, "authority_deleted");
    throw new HttpError(410, "account_deleted");
  }
  if (state.status === "suspended") {
    await markAccountSuspended(env.DB, accountId);
    throw new HttpError(403, "account_disabled");
  }

  await authority(env, accountId, { op: "activate_account" });
  await completeAccountActivation(env.DB, accountId);

  return { ...account, status: "active" };
}

export async function reconcileCustomerDeletion(
  env: Env,
  accountId: string,
): Promise<void> {
  if (!env.DB) throw new HttpError(503, "database_unavailable");

  const state = await authority<AccountAuthorityState>(env, accountId, {
    op: "get_account_state",
  });
  if (!state.tombstoned && state.status !== "deleted") {
    try {
      await authority(env, accountId, {
        op: "delete_account",
        tenant: accountId,
      });
    } catch (err: any) {
      if (err?.status !== 410) throw err;
    }
  }

  await recordAccountTombstone(env.DB, accountId, "customer_requested");
  await deleteAccountRecords(env.DB, accountId);

  try {
    await authority(env, accountId, { op: "confirm_deleted" });
  } catch {
    // ignore
  }
}

export async function deleteCustomerAccount(
  env: Env,
  accountId: string,
  deletionTokenHash?: string,
  retryTtl?: number,
): Promise<void> {
  if (!env.DB) throw new HttpError(503, "database_unavailable");

  // A D1 tombstone is the committed deletion marker: the fence already landed (or the account
  // was purged), so no new attempt may be opened. Complete whatever cleanup is left, which also
  // drives the authority to a tombstone when the DO side was interrupted.
  if (await isAccountTombstoned(env.DB, accountId)) {
    await finishDeletionCleanup(env, accountId);
    return;
  }

  // Step 0: Establish durable recovery intent in DO before the D1 fence. The DO allocates the
  // attempt generation that makes cancellation and supersession durable in D1.
  let generation = 0;
  try {
    const prep = await authority<{ prepared: boolean; generation?: number }>(
      env,
      accountId,
      {
        op: "prepare_deletion",
        tenant: accountId,
        deletionTokenHash,
        retryTtl,
      },
    );
    generation = Number(prep?.generation) || 0;
  } catch (err: any) {
    if (err?.status !== 410) throw err;
  }
  if (!Number.isSafeInteger(generation) || generation <= 0) {
    throw new HttpError(503, "deletion_attempt_unavailable");
  }

  // Step 1: Atomically register this attempt generation and commit the D1 lifecycle/deletion
  // fence (`accounts.status='deleted'`). The fence only commits while the durable attempt row is
  // 'prepared' for this generation, so a canceled or superseded attempt can never re-fence.
  let fence: DeletionFenceResult;
  try {
    fence = await fenceDeletionAttempt(env.DB, accountId, generation);
  } catch (error: any) {
    // The fence batch is atomic, so nothing committed. Release this attempt's recovery state
    // only after durably canceling it in D1, so a delayed retry of this fence cannot commit.
    await cancelAttempt(env, accountId, generation);
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }
  if (!fence.committed) {
    await cancelAttempt(env, accountId, generation);
    throw new HttpError(409, "deletion_canceled");
  }

  // Step 2: D1 is fenced against mutation publishing. Now commit deletion in DO:
  // revokes sessions, sets tombstone, marks status='deleted'.
  // Do NOT blindly restore D1 to active after its deletion fence;
  // D1 status remains 'deleted' so durable recovery alarm and customer retries
  // complete deletion coherently without exposing an active D1 state while DO is deleting.
  try {
    await authority(env, accountId, {
      op: "delete_account",
      tenant: accountId,
      deletionTokenHash,
      retryTtl,
    });
  } catch (err: any) {
    if (err?.status !== 410) {
      throw err;
    }
  }

  await finishDeletionCleanup(env, accountId);
}

/**
 * Durably cancel an attempt before releasing its DO recovery state. A stale attempt can only
 * abort the DO intent when the D1 attempt row still belongs to it and is not fenced, so a newer
 * attempt's committed recovery state can never be erased by a late loser.
 */
async function cancelAttempt(
  env: Env,
  accountId: string,
  generation: number,
): Promise<void> {
  if (!env.DB) throw new HttpError(503, "database_unavailable");
  const outcome = await cancelDeletionAttempt(env.DB, accountId, generation);
  if (outcome !== "canceled") return;
  try {
    await authority(env, accountId, {
      op: "abort_deletion",
      tenant: accountId,
      generation,
    });
  } catch {
    // The durable cancellation already blocks any later fence; the alarm retries cleanup.
  }
}

async function finishDeletionCleanup(
  env: Env,
  accountId: string,
): Promise<void> {
  if (!env.DB) throw new HttpError(503, "database_unavailable");
  // Step 3: Record tombstones in D1
  await recordAccountTombstone(env.DB, accountId, "customer_requested");

  // Step 4: Remove records from D1
  await deleteAccountRecords(env.DB, accountId);

  // Step 5: Confirm completed to clear pending DO deleting marker
  try {
    await authority(env, accountId, { op: "confirm_deleted" });
  } catch {
    // ignore
  }
}

export async function suspendCustomerAccount(
  env: Env,
  accountId: string,
): Promise<void> {
  if (!env.DB) throw new HttpError(503, "database_unavailable");

  const account = await findAccountById(env.DB, accountId);
  if (!account || account.status === "deleted") {
    throw new HttpError(404, "account_not_found");
  }

  // Step 1: Atomic D1 batch that sets status='suspended' AND cleans pending identities and profile updates.
  // If this batch fails (or any statement fails), it throws without mutating DO.
  try {
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE accounts SET status = 'suspended', updated_at = ? WHERE id = ? AND status != 'deleted'",
      ).bind(now(), accountId),
      env.DB.prepare(
        "DELETE FROM pending_profile_updates WHERE account_id = ?",
      ).bind(accountId),
      env.DB.prepare(
        "DELETE FROM identities WHERE account_id = ? AND status = 'pending'",
      ).bind(accountId),
    ]);
  } catch (error: any) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "database_unavailable");
  }

  // Step 2: Fencing D1 succeeded; now invoke DO suspend
  await authority(env, accountId, { op: "suspend_account" });
}

export async function validateAccountOwnership(
  env: Env,
  accountId: string,
): Promise<CustomerAccount> {
  if (!env.DB) throw new HttpError(503, "database_unavailable");
  if (await isAccountTombstoned(env.DB, accountId)) {
    throw new HttpError(410, "account_deleted");
  }

  const account = await findAccountById(env.DB, accountId);
  if (!account || account.status === "deleted") {
    throw new HttpError(404, "account_not_found");
  }

  const state = await authority<AccountAuthorityState>(env, accountId, {
    op: "get_account_state",
  });
  if (state.tombstoned || state.status === "deleted") {
    await recordAccountTombstone(env.DB, accountId, "authority_deleted");
    throw new HttpError(410, "account_deleted");
  }
  if (state.status === "suspended" || account.status === "suspended") {
    if (state.status === "suspended" && account.status !== "suspended") {
      await markAccountSuspended(env.DB, accountId);
    }
    throw new HttpError(403, "account_disabled");
  }
  if (account.status === "provisioning" || state.status === "provisioning") {
    throw new HttpError(403, "account_not_activated");
  }

  return account;
}

export async function linkCustomerIdentity(
  env: Env,
  accountId: string,
  identity: IdentityInput,
): Promise<CustomerIdentity> {
  const db = env.DB;
  if (!db) throw new HttpError(503, "database_unavailable");
  const account = await validateAccountOwnership(env, accountId);
  return linkIdentity(db, account.id, identity, async () => {
    const postState = await authority<AccountAuthorityState>(env, accountId, {
      op: "get_account_state",
    });
    if (postState.tombstoned || postState.status === "deleted") {
      await recordAccountTombstone(db, accountId, "authority_deleted");
      throw new HttpError(410, "account_deleted");
    }
    if (postState.status === "suspended") {
      await markAccountSuspended(db, accountId);
      throw new HttpError(403, "account_disabled");
    }
    if (postState.status === "provisioning") {
      throw new HttpError(403, "account_not_activated");
    }
  });
}

export async function updateCustomerProfile(
  env: Env,
  accountId: string,
  profile: ProfileInput,
): Promise<CustomerAccount> {
  const db = env.DB;
  if (!db) throw new HttpError(503, "database_unavailable");
  const account = await validateAccountOwnership(env, accountId);
  return updateAccountProfile(db, account.id, profile, async () => {
    const postState = await authority<AccountAuthorityState>(env, accountId, {
      op: "get_account_state",
    });
    if (postState.tombstoned || postState.status === "deleted") {
      await recordAccountTombstone(db, accountId, "authority_deleted");
      throw new HttpError(410, "account_deleted");
    }
    if (postState.status === "suspended") {
      await markAccountSuspended(db, accountId);
      throw new HttpError(403, "account_disabled");
    }
    if (postState.status === "provisioning") {
      throw new HttpError(403, "account_not_activated");
    }
  });
}
