import type {
  Env,
  Session,
  Grant,
  Principal,
  Proof,
  SecretPolicy,
  VaultConnection,
} from "../types";
import { HttpError, isWellFormedUnicode, now, reference } from "../security/primitives";
import {
  browserGrantOrigin,
  browserGrantOriginAllowed,
  browserGrantReceipt,
  browserGrantTenant,
  browserGrantView,
  type BrowserActionKind,
  type BrowserGrantAction,
  type BrowserGrantIssue,
  type BrowserGrantRecord,
} from "../security/browser-grant";
import { validateRequestPolicy } from "../security/policy";
import {
  cancelDeletionAttempt,
  deleteAccountRecords,
  findAccountById,
  isAccountTombstoned,
  recordAccountTombstone,
} from "../registry/store";
import {
  withRegistryDatabase,
  type RegistryDatabase,
} from "../registry/database";
import type { AuthorityStorage } from "./storage";

/**
 * The account authority business logic, free of any host runtime.
 *
 * Every decision the authority makes - session chains, DPoP replay, policy
 * checks, vault mediation, deletion recovery and usage accounting - lives in
 * AuthorityKernel. It depends only on the narrow AuthorityStorage port for
 * durable state, a background-work callback for post-response cleanup, and
 * the tenant instance name. A Cloudflare Durable Object supplies those from
 * its storage; a Node host supplies them from local SQLite. The rules are
 * identical either way, which is what lets one implementation serve both.
 */

export type Command = { op: string; [key: string]: unknown };
type SecretSaveRecord = {
  binding: string;
  connectionId: string;
  revision: number;
  expiresAt: number;
  status: "in_progress" | "saved" | "unknown" | "failed";
  reference?: string;
  verified?: true;
  resultStatus?: "unchanged" | "updated";
  agentHash?: string;
  agentIdentity?: string;
  alias?: string;
  intent?: "create" | "update" | "delete" | "ensure";
  policyBinding?: string;
  executorId?: string;
  target?: string;
};
type ProxyCapabilityRecord = {
  requestDigest: string;
  sessionHash: string;
  agentId?: string;
  jkt?: string;
  alias: string;
  policyBinding: string;
  connectionId?: string;
  connectionRevision?: number;
  url: string;
  method: string;
  expiresAt: number;
};
type PrivateInputRequest = {
  requestId: string;
  operationId: string;
  binding: string;
  agentIdentity: string;
  alias: string;
  policyBinding: string;
  connectionId: string;
  revision: number;
  intent: "create" | "update" | "ensure" | "delete";
  target: string;
  status: "pending" | "fulfilling" | "unknown" | "saved" | "rejected";
  retentionExpiresAt?: number;
  expiresAt: number;
  createdAt: number;
  reference?: string;
  verified?: true;
  resultStatus?: "unchanged" | "updated";
  executorId?: string;
};
type PrivateInputDashboardEntry = Pick<
  PrivateInputRequest,
  | "requestId"
  | "alias"
  | "intent"
  | "target"
  | "connectionId"
  | "status"
  | "expiresAt"
  | "createdAt"
>;

const CONNECT_REFERENCE = /^[0-9a-z]{26}#[^#\s]{1,768}$/;
const SERVICE_ACCOUNT_REFERENCE =
  /^[A-Za-z0-9_-]{1,128}#\/fields\/[A-Za-z0-9_-]{1,128}$/;
const BITWARDEN_PASSWORD_MANAGER_REFERENCE =
  /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}#\/(?:login\/(?:password|username|totp)|fields\/.+)$/;
const LASTPASS_REFERENCE = /^[1-9][0-9]{0,19}#\/(?:password|username|note)$/;
const CONNECT_TITLE = /^[a-zA-Z0-9][a-zA-Z0-9 .:_-]*$/;
const COMPANION_WRITE_PROVIDERS = [
  "bitwarden-password-manager",
  "lastpass",
  "onepassword-service-account",
] as const;

type CompanionWriteProvider = (typeof COMPANION_WRITE_PROVIDERS)[number];
const COMPANION_DELETE_PROVIDER = "onepassword-service-account";

function privateInputTargetValid(
  provider: string,
  intent: "create" | "update" | "ensure" | "delete",
  target: string,
): boolean {
  return providerWriteTargetValid(provider, intent, target);
}

function providerWriteTargetValid(
  provider: string,
  intent: "create" | "update" | "ensure" | "delete",
  target: string,
): boolean {
  if (intent === "create") {
    if (
      target !== target.trim() ||
      target.length === 0 ||
      target.length > 128 ||
      !isWellFormedUnicode(target) ||
      /[\u0000-\u001f\u007f]/.test(target)
    )
      return false;
    const companion = companionWriteProvider(provider);
    if (companion) return companionTargetValid(companion, "create", target);
    return CONNECT_TITLE.test(target);
  }
  const companion = companionWriteProvider(provider);
  if (companion) {
    if (
      intent === "delete" &&
      companion !== COMPANION_DELETE_PROVIDER
    )
      return false;
    return companionTargetValid(companion, intent, target);
  }
  return CONNECT_REFERENCE.test(target);
}

function companionWriteProvider(
  provider: string,
): CompanionWriteProvider | null {
  return COMPANION_WRITE_PROVIDERS.includes(provider as CompanionWriteProvider)
    ? (provider as CompanionWriteProvider)
    : null;
}

function companionTargetValid(
  provider: CompanionWriteProvider,
  intent: "create" | "update" | "ensure" | "delete",
  target: string,
): boolean {
  if (intent === "create")
    return (
      target === target.trim() &&
      target.length > 0 &&
      target.length <= 128 &&
      isWellFormedUnicode(target) &&
      !/[\\/#\u0000-\u001f\u007f]/.test(target)
    );
  if (provider === "bitwarden-password-manager")
    return BITWARDEN_PASSWORD_MANAGER_REFERENCE.test(target);
  if (provider === "lastpass") return LASTPASS_REFERENCE.test(target);
  return SERVICE_ACCOUNT_REFERENCE.test(target);
}

function savedReferenceValid(provider: string, reference: string): boolean {
  const companion = companionWriteProvider(provider);
  return companion
    ? companionTargetValid(companion, "update", reference)
    : CONNECT_REFERENCE.test(reference);
}

/**
 * The closed set of authority operations, declared once.
 *
 * This is the runtime authority for what an operation *is*. Two gates consult it, in the same
 * order the code runs: the first statement of `dispatch` (the single frame every operation enters)
 * and the first statement of `handle`. `dispatch` admits the set plus the one literal
 * `confirm_deleted` that it resolves itself before `handle` is entered; `handle` admits the set
 * only. Either gate refuses before its first state read, so an operation that no code here
 * implements can neither read nor mutate account state, whether or not any test or documentation
 * names it. `command.op` stays a plain `string` because commands arrive from the network;
 * `isRecognisedCommand` is the only place that widens a string into `AuthorityOperation`.
 *
 * The set is bound to the implementation, not maintained beside it: `AuthorityOperation` is the
 * union of these literals, and `handle` narrows `c.op` to it before its switch, so a `case` label
 * that is not listed here does not compile. That binds case labels to this list in one direction
 * only: a listed operation that loses its `case` still passes the membership check. The reverse
 * direction is caught instead by the switch's `default` branch after the lifecycle checks run, and
 * the mismatch between this array and the case labels is caught structurally by the equality
 * assertion in the registry test.
 *
 * `confirm_deleted` is deliberately absent: it is the one operation the Durable Object entry point
 * resolves itself, by exact literal comparison in `dispatch`, before `handle` is entered. It is
 * named once, in `dispatch`'s gate, rather than added here: adding it to the list would make it
 * reachable through `handle`'s switch, which does not implement it.
 */
const AUTHORITY_OPERATIONS = [
  "activate_account",
  "get_account_state",
  "prepare_deletion",
  "abort_deletion",
  "delete_account",
  "verify_deletion_credential",
  "suspend_account",
  "epoch",
  "get_session",
  "control_login",
  "rotate_session",
  "authenticate",
  "revoke_agent_session",
  "logout",
  "revoke",
  "put_grant",
  "create_consent",
  "device_review",
  "peek_grant",
  "approve_device",
  "redeem",
  "poll",
  "federate",
  "policies",
  "agent_connections",
  "inspect_secret",
  "authorize_secret_write",
  "prepare_private_input",
  "list_private_inputs",
  "claim_private_input",
  "complete_private_input",
  "save_policy",
  "update_policy_find_selector",
  "delete_policy",
  "enroll_executor",
  "issue_browser_grant",
  "redeem_browser_grant",
  "revoke_browser_grant",
  "revoke_executor",
  "list_executors",
  "list_browser_grants",
  "save_vault",
  "vault",
  "connections",
  "save_connection",
  "delete_connection",
  "rekey_connections",
  "account",
  "reserve_secret_save",
  "complete_secret_save",
  "audit",
  "record_audit",
  "execute",
  "create_proxy_capability",
  "revoke_proxy_capability",
  "execute_proxy_capability",
  "rate",
] as const;

type AuthorityOperation = (typeof AUTHORITY_OPERATIONS)[number];

const RECOGNISED_OPERATIONS: ReadonlySet<string> = new Set(
  AUTHORITY_OPERATIONS,
);

/** Narrow a network-supplied operation name into the closed set the authority implements. */
function isRecognisedCommand(value: string): value is AuthorityOperation {
  return RECOGNISED_OPERATIONS.has(value);
}

/**
 * The closed set of D1 account lifecycle statuses this module explicitly understands.
 *
 * It mirrors the set enforced by the `accounts` status triggers in `migrations/0003_*`; the
 * routing test parses both the migration and this declaration and requires them to be identical,
 * so the pair cannot drift silently. `active` is the only status this gate admits without an
 * exception list; the others have an exact per-command exception surface documented in
 * `ARCHITECTURE.md`. A status outside this set is never ordinary authorization material: it is
 * rejected with `403 account_status_unrecognized` (fail closed) instead of falling through as a
 * usable account.
 */
const ACCOUNT_STATUSES: readonly string[] = [
  "active",
  "provisioning",
  "suspended",
  "deleted",
];

/** One authority per tenant. Related decisions execute in a synchronous SQLite transaction. */

export class AuthorityKernel {
  private readonly storage: AuthorityStorage;
  private readonly env: Env;
  private readonly background: (promise: Promise<unknown>) => void;
  private readonly instanceName: string | null;

  constructor(deps: {
    storage: AuthorityStorage;
    env: Env;
    background: (promise: Promise<unknown>) => void;
    instanceName: string | null;
  }) {
    this.storage = deps.storage;
    this.env = deps.env;
    this.background = deps.background;
    this.instanceName = deps.instanceName;
    this.storage.exec(
      "CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires INTEGER)",
    );
    this.storage.exec(
      "CREATE INDEX IF NOT EXISTS records_expiry ON records(expires)",
    );
  }
  private get<T>(key: string): T | null {
    const row = this.storage
      .exec<{ value: string; expires: number | null }>(
        "SELECT value, expires FROM records WHERE key = ?",
        key,
      )
      .toArray()[0];
    return row && (row.expires === null || row.expires > now())
      ? (JSON.parse(row.value) as T)
      : null;
  }
  private requestDatabase(): RegistryDatabase {
    const db = withRegistryDatabase(this.env).DB;
    if (!db) throw new HttpError(503, "database_unavailable");
    return db;
  }
  private getAt<T>(key: string, at: number): T | null {
    const row = this.storage
      .exec<{ value: string; expires: number | null }>(
        "SELECT value, expires FROM records WHERE key = ?",
        key,
      )
      .toArray()[0];
    return row && (row.expires === null || row.expires > at)
      ? (JSON.parse(row.value) as T)
      : null;
  }
  private getStored<T>(key: string): T | null {
    const row = this.storage
      .exec<{ value: string }>("SELECT value FROM records WHERE key = ?", key)
      .toArray()[0];
    return row ? (JSON.parse(row.value) as T) : null;
  }
  private secretSaveNow(testNow: unknown): number {
    const testClockEnabled =
      (this.env as unknown as Record<string, unknown>)
        .SECRET_SAVE_TEST_CLOCK === "enabled";
    return testClockEnabled && Number.isSafeInteger(testNow)
      ? (testNow as number)
      : now();
  }
  private serviceAccountWritesEnabled(): boolean {
    return (
      (this.env as unknown as Record<string, unknown>)
        .ONEPASSWORD_SERVICE_ACCOUNT_WRITES === "enabled"
    );
  }
  private companionWritesEnabled(provider: string): boolean {
    if (provider === "onepassword-connect") return true;
    const companion = companionWriteProvider(provider);
    if (!companion) return false;
    if (companion === "onepassword-service-account")
      return this.serviceAccountWritesEnabled();
    return (
      (this.env as unknown as Record<string, unknown>)
        .AGENTSECRET_COMPANION_WRITES === "enabled"
    );
  }
  private put(key: string, value: unknown, expires?: number) {
    this.storage.exec(
      "INSERT OR REPLACE INTO records VALUES (?, ?, ?)",
      key,
      JSON.stringify(value),
      expires ?? null,
    );
  }
  private remove(key: string) {
    this.storage.exec("DELETE FROM records WHERE key = ?", key);
  }
  private privateInputDashboardEntry(
    request: PrivateInputRequest,
  ): PrivateInputDashboardEntry {
    return {
      requestId: request.requestId,
      alias: request.alias,
      intent: request.intent,
      target: request.target,
      connectionId: request.connectionId,
      status: request.status,
      expiresAt: request.expiresAt,
      createdAt: request.createdAt,
    };
  }
  private privateInputDashboardKey(request: PrivateInputRequest): string {
    return (
      "private-input-active:" +
      String(
        Number.isSafeInteger(request.createdAt) ? request.createdAt : now(),
      ).padStart(12, "0") +
      ":" +
      request.requestId
    );
  }
  private recoverExpiredPrivateInput(
    request: PrivateInputRequest,
    at: number,
  ): PrivateInputRequest {
    const saveOperation = this.getStored<SecretSaveRecord>(
      "secret-save:" + request.operationId,
    );
    if (
      saveOperation?.status === "saved" &&
      saveOperation.reference &&
      saveOperation.verified === true
    ) {
      request.status = "saved";
      request.reference = saveOperation.reference;
      request.verified = true;
      request.resultStatus = saveOperation.resultStatus;
    } else if (
      saveOperation?.status === "in_progress" &&
      saveOperation.expiresAt > at
    ) {
      return request;
    } else {
      if (saveOperation?.status === "in_progress") {
        this.put("secret-save:" + request.operationId, {
          ...saveOperation,
          status: "unknown",
        });
        this.releaseSecretSaveLock(
          saveOperation.connectionId,
          request.operationId,
        );
      }
      request.status = "unknown";
    }
    request.expiresAt = at + 91 * 86400;
    delete request.retentionExpiresAt;
    this.put("private-input:" + request.requestId, request);
    this.put(
      "private-input-operation:" + request.operationId,
      request.requestId,
    );
    this.remove("private-input-active:" + request.requestId);
    if (request.status === "unknown")
      this.put(
        this.privateInputDashboardKey(request),
        this.privateInputDashboardEntry(request),
      );
    else this.remove(this.privateInputDashboardKey(request));
    return request;
  }
  private releaseSecretSaveLock(connectionId: string, operationId: string) {
    const lockKey = "secret-save-active:" + connectionId;
    if (this.get<string>(lockKey) === operationId) this.remove(lockKey);
  }
  private retireExpiredSecretSaveLock(connectionId: string, at: number) {
    const lockKey = "secret-save-active:" + connectionId;
    const operationId = this.get<string>(lockKey);
    if (!operationId) return;
    const operationKey = "secret-save:" + operationId;
    const operation = this.getStored<SecretSaveRecord>(operationKey);
    if (operation?.status !== "in_progress" || operation.expiresAt > at) return;
    this.put(operationKey, { ...operation, status: "unknown" });
    this.releaseSecretSaveLock(connectionId, operationId);
  }
  private epoch(): number {
    return this.get<number>("epoch") || 0;
  }
  /**
   * The deletion retry window is owned by the authority: whatever a caller asks for is clamped
   * into a finite 1..60 second window, so no request, header or transport can extend (or
   * disable) the window in which a deleted credential may still complete the deletion.
   */
  private deletionTtl(value: unknown): number {
    const ttl = Number(value);
    if (!Number.isFinite(ttl)) return 60;
    return Math.min(60, Math.max(1, Math.floor(ttl)));
  }
  /**
   * Commit authority-side deletion: revoke every session by bumping the epoch, publish the
   * tombstone and drop all records except the tombstone, status, epoch and the deletion
   * recovery markers. Callers must have established that the deletion is terminal.
   */
  private applyCommittedDeletion(): void {
    // The pending marker is left in place here: until D1 records are purged the marker is what
    // lets the alarm finish the cleanup if this caller dies. Callers that have completed the D1
    // side clear it explicitly.
    this.put("account:tombstone", { deleted: true, deletedAt: now() });
    this.put("account:status", "deleted");
    this.put("epoch", this.epoch() + 1);
    this.storage.exec(
      "DELETE FROM records WHERE key NOT IN ('account:tombstone', 'account:status', 'epoch', 'account:deleting', 'account:deletion_capability', 'account:deletion_deadline', 'account:deletion_generation')",
    );
  }
  /**
   * Terminal confirmation for a deletion. The recovery marker may only be cleared once the
   * deletion is provably terminal: either the authority committed the tombstone, or D1 already
   * holds the account tombstone (the two commits were interrupted between each other). In the
   * latter case the authority deletion is completed here, so a retry converges on a tombstoned,
   * session-free authority with a bumped epoch instead of a live account behind a cleared
   * marker.
   */
  private async confirmDeletion(accountId: string): Promise<boolean> {
    const db = this.requestDatabase();
    const d1Tombstoned = accountId
      ? await isAccountTombstoned(db, accountId)
      : false;
    return this.storage.transactionSync(() => {
      const committed =
        Boolean(this.get("account:tombstone")) ||
        this.get<string>("account:status") === "deleted";
      if (committed) {
        this.remove("account:deleting");
        return true;
      }
      if (!d1Tombstoned) throw new HttpError(409, "deletion_incomplete");
      this.applyCommittedDeletion();
      this.remove("account:deleting");
      return true;
    });
  }
  private session(p: Principal): Session {
    if (p.bootstrap) return p;
    const session = this.get<Session>("session:" + p.hash);
    if (!session || !this.validSessionChain(p.hash, session))
      throw new HttpError(401, "invalid_token");
    return session;
  }
  private validSessionChain(
    hash: string,
    first: Session,
    allowSupersededFirst = false,
  ): boolean {
    const seen = new Set<string>();
    let current: Session | undefined = first;
    let currentHash = hash;
    while (current) {
      if (
        seen.has(currentHash) ||
        current.epoch !== this.epoch() ||
        current.exp <= now() ||
        (seen.size === 0 &&
          !allowSupersededFirst &&
          current.purpose === "control" &&
          current.superseded)
      )
        return false;
      seen.add(currentHash);
      if (!current.parent) return true;
      currentHash = current.parent;
      current = this.get<Session>("session:" + currentHash) || undefined;
    }
    return false;
  }
  private descendsFrom(hash: string, ancestorHash: string): boolean {
    const first = this.get<Session>("session:" + hash);
    if (!first || !this.validSessionChain(hash, first)) return false;
    const seen = new Set<string>();
    let currentHash = hash;
    let current: Session | undefined = first;
    while (current) {
      if (currentHash === ancestorHash) return true;
      if (seen.has(currentHash) || !current.parent) return false;
      seen.add(currentHash);
      currentHash = current.parent;
      current = this.get<Session>("session:" + currentHash) || undefined;
    }
    return false;
  }
  private control(p: Principal) {
    const session = this.session(p);
    if (session.purpose !== "control" || !session.scopes.includes("admin"))
      throw new HttpError(403, "control_session_required");
    return session;
  }
  private authenticatePrivateInputAgent(
    p: Principal,
    request: PrivateInputRequest,
    executorId: unknown,
    proof: unknown,
  ) {
    const session = this.session(p);
    const executor = (
      this.get<Array<Record<string, unknown>>>("executors") || []
    ).find((item) => item.executorId === executorId);
    const candidate = proof as Proof;
    if (
      session.purpose !== "agent" ||
      request.agentIdentity !== (session.agentId || session.jkt) ||
      !session.scopes.includes("secrets:write") ||
      typeof executorId !== "string" ||
      !/^exe_[A-Za-z0-9_-]{43}$/u.test(executorId) ||
      !executor ||
      executor.thumbprint !== candidate?.jkt ||
      !candidate?.jti
    )
      throw new HttpError(403, "trusted_executor_required");
    this.replay(candidate);
    return session;
  }
  private currentPrivateInputPolicy(request: PrivateInputRequest) {
    const policy = (this.get<SecretPolicy[]>("policies") || []).find(
      (item) => item.alias === request.alias,
    );
    if (
      !policy ||
      JSON.stringify(policy) !== request.policyBinding ||
      !policy.secretWrite?.[
        request.intent === "ensure" ? "update" : request.intent
      ]
    )
      throw new HttpError(409, "private_input_policy_changed");
    return policy;
  }
  private authenticateTrustedExecutor(
    p: Principal,
    executorId: unknown,
    proof: unknown,
  ): void {
    const session = this.session(p);
    const executor = (
      this.get<Array<Record<string, unknown>>>("executors") || []
    ).find((item) => item.executorId === executorId);
    const candidate = proof as Proof;
    if (
      session.purpose !== "agent" ||
      !session.scopes.includes("secrets:write") ||
      typeof executorId !== "string" ||
      !/^exe_[A-Za-z0-9_-]{43}$/u.test(executorId) ||
      !executor ||
      executor.thumbprint !== candidate?.jkt ||
      !candidate?.jti
    )
      throw new HttpError(403, "trusted_executor_required");
    this.replay(candidate);
  }
  private replay(proof: Proof) {
    if (proof.expiresAt <= now())
      throw new HttpError(401, "invalid_dpop_proof");
    const key = "proof:" + proof.jkt + ":" + proof.jti;
    if (this.get(key)) throw new HttpError(401, "replayed_proof");
    this.put(key, true, proof.expiresAt);
  }
  async dispatch(command: Command): Promise<unknown> {
    // Closed-set gate, first statement of the single frame every operation passes through: it runs
    // before the alarm branch, before the `confirm_deleted` branch and before the transaction that
    // enters `handle`, so an operation this module does not implement can neither read nor mutate
    // account state, whatever state the account is in. Admitting the declared set plus exactly the
    // one literal `dispatch` resolves itself keeps a single source of truth: there is no second,
    // derived set that could drift from `AUTHORITY_OPERATIONS`.
    //
    // Scope, honestly: this is a property of the code as written, not of every future edit. A
    // statement inserted ABOVE this one is not prevented at run time - it runs first and its return
    // answers for itself. It is detected, not prevented: the registry test rejects the gate's
    // position, and a probe aimed at the name the inserted return serves observes it serving that
    // name. What the code below guarantees is narrower than "no state access before the gate": the
    // tenant routing layer reads D1 `accounts` to resolve the tenant before this object is reached,
    // and inside `dispatch`'s own body no account storage read or write happens before the refusal
    // below. The registry test pins the gate's position so such an edit fails a check instead of
    // being silently accepted.
    if (!isRecognisedCommand(command.op) && command.op !== "confirm_deleted") {
      return { ok: false, status: 400, code: "invalid_authority_command" };
    }
    try {
      if (
        command.op === "delete_account" ||
        command.op === "prepare_deletion"
      ) {
        // Durable alarm scheduling happens before revoking sessions or mutating state;
        // if alarm scheduling fails, fail before state mutation.
        await this.storage.setAlarm(Date.now() + 10_000);
      }
      const result =
        command.op === "confirm_deleted"
          ? await this.confirmDeletion(
              String(
                command.tenant || command.accountId || this.instanceName || "",
              ),
            )
          : this.storage.transactionSync(() => this.handle(command));
      this.background(this.scheduleCleanup());
      return { ok: true, value: result };
    } catch (error) {
      if (error instanceof HttpError)
        return { ok: false, status: error.status, code: error.code };
      throw error;
    }
  }
  private handle(c: Command): unknown {
    // Second closed-set gate, first statement of the handler body. `dispatch` has already refused
    // anything outside the set plus `confirm_deleted`, so this is defence in depth and, more
    // importantly, the narrowing that binds the `switch` below to `AuthorityOperation`: a `case`
    // label missing from `AUTHORITY_OPERATIONS` does not compile. The set is the same shared one, so
    // the two gates cannot disagree. `400 invalid_authority_command` stays distinguishable from the
    // routing gate's tenant (`401 unknown_tenant`), deletion (`410 account_deleted`) and suspension
    // (`403 account_disabled`, `403 account_not_activated`) responses.
    if (!isRecognisedCommand(c.op)) {
      throw new HttpError(400, "invalid_authority_command");
    }
    if (
      c.op !== "get_account_state" &&
      c.op !== "activate_account" &&
      c.op !== "delete_account" &&
      c.op !== "prepare_deletion" &&
      c.op !== "abort_deletion" &&
      c.op !== "verify_deletion_credential" &&
      c.op !== "suspend_account" &&
      c.op !== "rate"
    ) {
      if (
        this.get("account:tombstone") ||
        this.get("account:status") === "deleted"
      ) {
        throw new HttpError(410, "account_deleted");
      }
      if (this.get("account:status") === "suspended") {
        throw new HttpError(403, "account_disabled");
      }
      if (this.get("account:status") === "provisioning") {
        throw new HttpError(403, "account_not_activated");
      }
    }
    const p = c.principal as Principal;
    switch (c.op) {
      case "activate_account": {
        if (
          this.get("account:tombstone") ||
          this.get("account:status") === "deleted"
        ) {
          throw new HttpError(410, "account_deleted");
        }
        if (this.get("account:status") === "suspended") {
          throw new HttpError(403, "account_disabled");
        }
        this.put("account:status", "active");
        this.put("account:activated_at", now());
        return { status: "active", activatedAt: now() };
      }
      case "get_account_state": {
        const tombstone = this.get<{ deleted: boolean; deletedAt: number }>(
          "account:tombstone",
        );
        const status = tombstone
          ? "deleted"
          : this.get<string>("account:status") || "active";
        const deadline = this.get<{
          hash: string;
          exp: number;
          initializedAt: number;
        }>("account:deletion_deadline");
        const cap = this.get<{ hash: string; exp: number }>(
          "account:deletion_capability",
        );
        // Capability material (the credential hash) is never published: callers only learn
        // whether a retry window is open and when it closes. The stored expiry stays observable
        // after it passes so a client can tell "expired" from "never existed".
        const deletedExp = Math.max(deadline?.exp ?? 0, cap?.exp ?? 0);
        return {
          status,
          tombstoned: Boolean(tombstone),
          activatedAt: this.get<number>("account:activated_at") || null,
          epoch: this.epoch(),
          hasDeletionCapability: deletedExp > now(),
          deletionDeadline: deletedExp > 0 ? { exp: deletedExp } : null,
        };
      }
      case "prepare_deletion": {
        const tenantId =
          (c.tenant as string) || (c.accountId as string) || null;
        const attempt = this.prepareDeletionAttempt(tenantId);
        if (!attempt) {
          throw new HttpError(409, "deletion_attempt_unavailable");
        }
        let isNew = false;
        let deadline = this.get<{
          hash: string;
          exp: number;
          initializedAt: number;
        }>("account:deletion_deadline");
        if (!deadline && c.deletionTokenHash) {
          const ttl = this.deletionTtl(c.retryTtl);
          const exp = now() + ttl;
          deadline = {
            hash: String(c.deletionTokenHash),
            exp,
            initializedAt: now(),
          };
          this.put("account:deletion_deadline", deadline);
          this.put(
            "account:deletion_capability",
            { hash: deadline.hash, exp: deadline.exp },
            deadline.exp,
          );
          isNew = true;
        } else if (deadline) {
          if (now() >= deadline.exp) {
            throw new HttpError(401, "unauthorized");
          }
          if (
            c.deletionTokenHash &&
            String(c.deletionTokenHash) !== deadline.hash
          ) {
            throw new HttpError(401, "unauthorized");
          }
        }
        return {
          prepared: true,
          isNew,
          deadline: deadline?.exp ?? null,
          generation: attempt.generation,
        };
      }
      case "abort_deletion": {
        // Retries and stale attempts must never clear established recovery/deadline state.
        if (
          this.get("account:tombstone") ||
          this.get("account:status") === "deleted"
        ) {
          return { aborted: false };
        }
        const existing = this.get<{ generation?: number }>("account:deleting");
        const current = Number(existing?.generation);
        if (!existing || !Number.isSafeInteger(current) || current <= 0) {
          return { aborted: false };
        }
        // Only the attempt that owns the current generation may release it. "Older" is not an
        // answer here: a stale abort must not erase a newer attempt's recovery state.
        const requested = Number(c.generation);
        if (!Number.isSafeInteger(requested) || requested !== current) {
          return { aborted: false };
        }
        this.remove("account:deleting");
        this.remove("account:deletion_capability");
        this.remove("account:deletion_deadline");
        return { aborted: true };
      }
      case "delete_account": {
        const tenantId =
          (c.tenant as string) || (c.accountId as string) || null;
        this.prepareDeletionAttempt(tenantId);
        let deadline = this.get<{
          hash: string;
          exp: number;
          initializedAt: number;
        }>("account:deletion_deadline");
        if (!deadline && c.deletionTokenHash) {
          const ttl = this.deletionTtl(c.retryTtl);
          const exp = now() + ttl;
          deadline = {
            hash: String(c.deletionTokenHash),
            exp,
            initializedAt: now(),
          };
          this.put("account:deletion_deadline", deadline);
          this.put(
            "account:deletion_capability",
            { hash: deadline.hash, exp: deadline.exp },
            deadline.exp,
          );
        } else if (deadline) {
          // Revalidate deadline at deletion commit
          if (now() >= deadline.exp) {
            throw new HttpError(401, "unauthorized");
          }
          if (
            c.deletionTokenHash &&
            String(c.deletionTokenHash) !== deadline.hash
          ) {
            throw new HttpError(401, "unauthorized");
          }
        }
        this.applyCommittedDeletion();
        return { status: "deleted", deletedAt: now() };
      }
      case "verify_deletion_credential": {
        const deadline = this.get<{
          hash: string;
          exp: number;
          initializedAt: number;
        }>("account:deletion_deadline");
        if (deadline) {
          if (deadline.hash !== String(c.hash) || deadline.exp <= now()) {
            throw new HttpError(401, "unauthorized");
          }
          return { authorized: true };
        }
        const cap = this.get<{ hash: string; exp: number }>(
          "account:deletion_capability",
        );
        if (cap) {
          if (cap.hash !== String(c.hash) || cap.exp <= now()) {
            throw new HttpError(401, "unauthorized");
          }
          return { authorized: true };
        }
        throw new HttpError(401, "unauthorized");
      }
      case "suspend_account": {
        if (
          this.get("account:tombstone") ||
          this.get("account:status") === "deleted"
        ) {
          throw new HttpError(410, "account_deleted");
        }
        if (this.get("account:status") !== "suspended") {
          this.put("account:status", "suspended");
          this.put("epoch", this.epoch() + 1);
        }
        return { status: "suspended" };
      }
      case "epoch":
        return this.epoch();
      case "get_session":
        return this.get<Session>("session:" + String(c.hash));
      case "control_login": {
        if (this.get("account:status") === "provisioning") {
          throw new HttpError(403, "account_not_activated");
        }
        const session = c.session as Session;
        this.put(
          "session:" + String(c.hash),
          { ...session, epoch: this.epoch() },
          session.exp,
        );
        return true;
      }
      case "rotate_session": {
        // Rotation replaces the digest of a live customer session. It is deliberately not a way to
        // create one: the record must already exist, so a bootstrap principal (which has no stored
        // record) cannot use this operation to mint a session, and the replacement record is
        // derived from the stored one rather than from the command, so a caller cannot change the
        // tenant, scopes, audience or expiry it rotates into. The two writes run inside the
        // transaction `handle` opens, and every edge reads the session through this same object.
        if (!this.get<Session>("session:" + p.hash))
          throw new HttpError(401, "invalid_token");
        const current = this.control(p);
        // Keep the old record as a rotation ancestor: approved grants and agent sessions bind to
        // this digest. Descendants remain valid only while each ancestor remains live.
        this.put(
          "session:" + p.hash,
          { ...current, superseded: true },
          current.exp,
        );
        this.put(
          "session:" + String(c.hash),
          {
            ...current,
            parent: p.hash,
            refreshedAt: now(),
            epoch: this.epoch(),
          },
          current.exp,
        );
        return true;
      }
      case "authenticate": {
        const session = this.session(p);
        if (session.purpose === "agent") {
          const proof = c.proof as Proof | undefined;
          if (!proof || proof.jkt !== session.jkt)
            throw new HttpError(401, "invalid_dpop_proof");
          if (c.consumeProof) this.replay(proof);
        }
        return session;
      }
      case "revoke_agent_session": {
        const session = this.session(p);
        if (session.purpose !== "agent")
          throw new HttpError(403, "agent_session_required");
        this.remove("session:" + p.hash);
        return true;
      }
      case "logout":
        this.control(p);
        // The epoch is shared by sessions and grants, so logout also invalidates agent sessions
        // and grants bound to any retained rotation ancestor, including after a restart.
        this.put("epoch", this.epoch() + 1);
        return true;
      case "revoke": {
        this.control(p);
        if (c.hash) this.remove("session:" + String(c.hash));
        else this.put("epoch", this.epoch() + 1);
        return true;
      }
      case "put_grant": {
        const grant = c.grant as Grant;
        if (grant.kind === "code") this.control(p);
        else this.replay(c.proof as Proof);
        if (grant.status === "approved" && grant.kind === "code") {
          const consentKey = String(c.consentKey || "");
          const reviewed = consentKey && this.get<any>("consent:" + consentKey);
          const aliases = grant.aliases || [];
          const bindings = this.selectBindings<string>(
            reviewed?.bindings,
            aliases,
          );
          const connectionBindings = this.connectionBindings(aliases);
          const reviewedConnections = this.selectBindings(
            reviewed?.connectionBindings,
            Object.keys(connectionBindings),
          );
          if (
            !reviewed ||
            reviewed.exp <= now() ||
            aliases.some((alias) => !reviewed.aliases.includes(alias)) ||
            aliases.some((alias) => !bindings[alias]) ||
            !this.sameBindings(bindings, this.bindPolicies(aliases)) ||
            !this.sameBindings(reviewedConnections, connectionBindings) ||
            reviewed.clientId !== grant.clientId ||
            (reviewed.parent !== (grant.parent || "") &&
              (!grant.parent ||
                !this.descendsFrom(grant.parent, reviewed.parent))) ||
            JSON.stringify(reviewed.scopes) !== JSON.stringify(grant.scopes) ||
            reviewed.requestDigest !== c.requestDigest
          )
            throw new HttpError(409, "consent_stale");
          grant.policyBindings = bindings;
          grant.exp = Math.min(grant.exp, reviewed.grantExp);
          grant.sessionExp = Math.min(
            grant.sessionExp || reviewed.sessionExp,
            reviewed.sessionExp,
          );
          this.remove("consent:" + consentKey);
        }
        this.put(
          "grant:" + String(c.hash),
          { ...grant, epoch: this.epoch() },
          grant.exp,
        );
        if (grant.userCode)
          this.put("device-code:" + grant.userCode, String(c.hash), grant.exp);
        return true;
      }
      case "create_consent": {
        const session = this.control(p);
        const policies = this.get<SecretPolicy[]>("policies") || [];
        const requestedAliases = c.aliases;
        if (
          requestedAliases !== undefined &&
          (!Array.isArray(requestedAliases) || requestedAliases.length > 30)
        )
          throw new HttpError(400, "invalid_alias_grant");
        const consentScopes = c.scopes as string[];
        const eligiblePolicies = consentScopes.includes("secrets:write")
          ? policies.filter(
              (policy) =>
                policy.secretWrite &&
                (policy.secretWrite.create ||
                  policy.secretWrite.update ||
                  policy.secretWrite.delete),
            )
          : policies;
        const aliases = [
          ...new Set(
            (requestedAliases as string[] | undefined) ??
              eligiblePolicies.map((item) => item.alias),
          ),
        ];
        if (
          aliases.some(
            (alias) =>
              !policies.some((policy) => policy.alias === alias) ||
              (session.aliases !== undefined &&
                !session.aliases.includes(alias)),
          )
        )
          throw new HttpError(400, "invalid_alias_grant");
        if (
          aliases.some(
            (alias) => !eligiblePolicies.some((item) => item.alias === alias),
          )
        )
          throw new HttpError(403, "secret_write_not_owner_granted");
        const key = String(c.key);
        const bindings = this.bindPolicies(aliases);
        const connectionBindings = this.connectionBindings(aliases);
        const reviewed = {
          exp: Math.min(now() + 600, session.exp),
          grantExp: Math.min(now() + 300, session.exp),
          sessionExp: Math.min(now() + 3600, session.exp),
          bindings,
          connectionBindings,
          aliases,
          clientId: String(c.clientId),
          parent: p.bootstrap ? "" : p.hash,
          scopes: c.scopes,
          requestDigest: String(c.requestDigest),
        };
        this.put("consent:" + key, reviewed, reviewed.exp);
        return {
          aliases,
          policies: policies.filter((item) => aliases.includes(item.alias)),
          connections: Object.values(connectionBindings),
        };
      }
      case "peek_grant":
        return this.get<Grant>("grant:" + String(c.hash));
      case "approve_device": {
        const parent = this.control(p);
        const key = this.get<string>("device-code:" + String(c.userCode));
        const grant = key && this.get<Grant>("grant:" + key);
        const consentKey = String(c.consentKey || "");
        const reviewed = consentKey && this.get<any>("consent:" + consentKey);
        if (
          !grant ||
          grant.status !== "pending" ||
          grant.exp <= now() ||
          grant.epoch !== this.epoch() ||
          !reviewed ||
          reviewed.kind !== "device" ||
          reviewed.exp <= now() ||
          reviewed.userCode !== c.userCode ||
          (reviewed.parent !== p.hash &&
            !this.descendsFrom(p.hash, reviewed.parent)) ||
          reviewed.grantKey !== key ||
          (() => {
            const { lastPoll: _reviewedPoll, ...reviewedAuthorization } =
              reviewed.grant;
            const { lastPoll: _currentPoll, ...currentAuthorization } = grant;
            return (
              JSON.stringify(reviewedAuthorization) !==
              JSON.stringify(currentAuthorization)
            );
          })()
        )
          throw new HttpError(409, "consent_stale");
        const selected = c.aliases as string[];
        if (
          !Array.isArray(selected) ||
          selected.some((alias) => !reviewed.aliases.includes(alias))
        )
          throw new HttpError(400, "invalid_alias_grant");
        const currentBindings = this.bindPolicies(selected);
        const reviewedBindings = this.selectBindings(
          reviewed.bindings,
          selected,
        );
        const currentConnections = this.connectionBindings(selected);
        const reviewedConnections = this.selectBindings(
          reviewed.connectionBindings,
          Object.keys(currentConnections),
        );
        if (
          selected.some((alias) => !reviewedBindings[alias]) ||
          !this.sameBindings(currentBindings, reviewedBindings) ||
          !this.sameBindings(currentConnections, reviewedConnections)
        )
          throw new HttpError(409, "consent_stale");
        const requestedScopes = grant.requestedScopes || [
          "secrets:proxy",
          "secrets:read",
        ];
        const writeRequested = requestedScopes.includes("secrets:write");
        const selectedPolicies = this.get<SecretPolicy[]>("policies") || [];
        if (
          writeRequested &&
          selected.some((alias) => {
            const policy = selectedPolicies.find(
              (item) => item.alias === alias,
            );
            return (
              !policy?.secretWrite ||
              (!policy.secretWrite.create &&
                !policy.secretWrite.update &&
                !policy.secretWrite.delete)
            );
          })
        )
          throw new HttpError(403, "secret_write_not_owner_granted");
        grant.status = "approved";
        grant.parent = p.bootstrap ? undefined : p.hash;
        grant.scopes = [...new Set(requestedScopes)].filter(
          (scope) =>
            parent.scopes.includes(scope) || parent.scopes.includes("admin"),
        );
        if (writeRequested && !grant.scopes.includes("secrets:write"))
          throw new HttpError(403, "insufficient_scope");
        grant.aliases = [...new Set(selected)];
        if (
          grant.aliases.some(
            (alias) =>
              parent.aliases !== undefined && !parent.aliases.includes(alias),
          )
        )
          throw new HttpError(400, "invalid_alias_grant");
        grant.policyBindings = currentBindings;
        grant.exp = Math.min(grant.exp, parent.exp);
        grant.sessionExp = Math.min(
          reviewed.sessionExp,
          now() + 3600,
          parent.exp,
        );
        this.put("grant:" + key, grant, grant.exp);
        this.remove("device-code:" + grant.userCode);
        this.remove("consent:" + consentKey);
        return true;
      }
      case "device_review": {
        const parent = this.control(p);
        const userCode = String(c.userCode);
        const grantKey = this.get<string>("device-code:" + userCode);
        const grant = grantKey && this.get<Grant>("grant:" + grantKey);
        if (
          !grant ||
          grant.kind !== "device" ||
          grant.status !== "pending" ||
          grant.exp <= now() ||
          grant.epoch !== this.epoch()
        )
          throw new HttpError(400, "invalid_grant");
        const key = String(c.consentKey);
        const aliases = [...new Set(grant.aliases || [])];
        const requestedScopes = grant.requestedScopes || [
          "secrets:proxy",
          "secrets:read",
        ];
        const policies = this.get<SecretPolicy[]>("policies") || [];
        const reviewAliases = requestedScopes.includes("secrets:write")
          ? aliases.filter((alias) => {
              const policy = policies.find((item) => item.alias === alias);
              return (
                !!policy?.secretWrite &&
                !!(
                  policy.secretWrite.create ||
                  policy.secretWrite.update ||
                  policy.secretWrite.delete
                )
              );
            })
          : aliases;
        const bindings = this.bindPolicies(reviewAliases);
        const connectionBindings = this.connectionBindings(reviewAliases);
        const sessionExp = Math.min(now() + 3600, parent.exp);
        this.put(
          "consent:" + key,
          {
            kind: "device",
            exp: Math.min(now() + 600, grant.exp, parent.exp),
            sessionExp,
            userCode,
            grantKey,
            grant: structuredClone(grant),
            parent: p.hash,
            aliases: reviewAliases,
            bindings,
            connectionBindings,
          },
          Math.min(now() + 600, grant.exp, parent.exp),
        );
        return {
          grant,
          sessionExp,
          policies: policies.filter((item) =>
            reviewAliases.includes(item.alias),
          ),
          connections: Object.values(connectionBindings),
        };
      }
      case "redeem": {
        if (this.get("account:status") === "provisioning") {
          throw new HttpError(403, "account_not_activated");
        }
        const key = "grant:" + String(c.hash);
        const grant = this.get<Grant>(key);
        if (
          !grant ||
          grant.exp <= now() ||
          grant.epoch !== this.epoch() ||
          (grant.parent &&
            (() => {
              const parent = this.get<Session>("session:" + grant.parent);
              return (
                !parent || !this.validSessionChain(grant.parent, parent, true)
              );
            })())
        )
          throw new HttpError(400, "invalid_grant");
        if (grant.status !== "approved")
          throw new HttpError(400, "authorization_pending");
        if (
          !grant.policyBindings ||
          (grant.aliases || []).some((alias) => !grant.policyBindings?.[alias])
        )
          throw new HttpError(400, "invalid_grant");
        if (JSON.stringify(grant) !== c.expected)
          throw new HttpError(400, "invalid_grant");
        const proof = c.proof as Proof;
        if (!proof || (grant.jkt && grant.jkt !== proof.jkt))
          throw new HttpError(400, "invalid_dpop_proof");
        this.replay(proof);
        const session = c.session as Session;
        const parent = grant.parent
          ? this.get<Session>("session:" + grant.parent)
          : null;
        session.exp = Math.min(
          session.exp,
          grant.sessionExp || grant.exp,
          parent?.exp || session.exp,
        );
        if (session.exp <= now()) throw new HttpError(400, "invalid_grant");
        session.epoch = this.epoch();
        session.parent = grant.parent;
        session.audience = grant.audience;
        session.scopes = grant.scopes;
        session.aliases = grant.aliases;
        session.policyBindings = grant.policyBindings;
        this.put("session:" + String(c.tokenHash), session, session.exp);
        this.remove(key);
        if (grant.userCode) this.remove("device-code:" + grant.userCode);
        return session;
      }
      case "poll": {
        const key = "grant:" + String(c.hash);
        const grant = this.get<Grant>(key);
        if (
          !grant ||
          grant.status !== "pending" ||
          grant.epoch !== this.epoch()
        )
          throw new HttpError(400, "invalid_grant");
        const proof = c.proof as Proof;
        if (grant.jkt !== proof.jkt)
          throw new HttpError(400, "invalid_dpop_proof");
        this.replay(proof);
        const slow = !!grant.lastPoll && grant.lastPoll + 5 > now();
        grant.lastPoll = now();
        this.put(key, grant, grant.exp);
        return slow ? "slow_down" : "authorization_pending";
      }
      case "federate": {
        const session = c.session as Session;
        this.replay(c.proof as Proof);
        session.policyBindings = this.bindPolicies(session.aliases || []);
        const key = "assertion:" + String(c.assertionHash);
        if (this.get(key)) throw new HttpError(401, "assertion_replayed");
        this.put(key, true, Number(c.assertionExp));
        session.epoch = this.epoch();
        this.put("session:" + String(c.tokenHash), session, session.exp);
        return session;
      }
      case "policies": {
        const policies = this.get<SecretPolicy[]>("policies") || [];
        // Workload/bootstrap callers have no customer policy view. Even when routed to a
        // configured legacy authority, an absent principal cannot enumerate that tenant's data.
        if (!p || p.bootstrap) return [];
        const session = this.session(p);
        if (
          !session.scopes.includes("secrets:read") &&
          !session.scopes.includes("admin")
        )
          throw new HttpError(403, "insufficient_scope");
        return session.aliases === undefined
          ? policies
          : policies.filter((policy) =>
              session.aliases!.includes(policy.alias),
            );
      }
      case "agent_connections": {
        if (!p || p.bootstrap)
          throw new HttpError(401, "agent_session_required");
        const session = this.session(p);
        if (
          !session.scopes.includes("secrets:read") &&
          !session.scopes.includes("admin")
        )
          throw new HttpError(403, "insufficient_scope");
        const policies = this.get<SecretPolicy[]>("policies") || [];
        const boundPolicies = policies.filter(
          (policy) =>
            (session.aliases === undefined ||
              session.aliases.includes(policy.alias)) &&
            session.policyBindings?.[policy.alias] === JSON.stringify(policy) &&
            typeof policy.connectionId === "string",
        );
        const connections =
          this.get<VaultConnection[]>("vault:connections") || [];
        return boundPolicies.flatMap((policy) => {
          const connection = connections.find(
            (item) => item.id === policy.connectionId,
          );
          return connection
            ? [
                {
                  alias: policy.alias,
                  id: connection.id,
                  provider: connection.provider,
                  revision: connection.revision,
                },
              ]
            : [];
        });
      }
      case "inspect_secret": {
        if (!p || p.bootstrap)
          throw new HttpError(401, "customer_session_required");
        const session = this.session(p);
        if (
          !session.scopes.includes("secrets:read") &&
          !session.scopes.includes("admin")
        )
          throw new HttpError(403, "insufficient_scope");
        const alias = String(c.alias);
        if (session.aliases !== undefined && !session.aliases.includes(alias))
          throw new HttpError(403, "alias_forbidden");
        const policy = (this.get<SecretPolicy[]>("policies") || []).find(
          (item) => item.alias === alias,
        );
        if (!policy) throw new HttpError(404, "alias_not_found");
        if (
          session.purpose === "agent" &&
          (!session.policyBindings?.[alias] ||
            session.policyBindings[alias] !== JSON.stringify(policy))
        )
          throw new HttpError(
            403,
            session.policyBindings
              ? "grant_policy_changed"
              : "grant_policy_binding_missing",
          );
        if (p.tenant !== "default" && !policy.connectionId)
          throw new HttpError(503, "vault_connection_required");
        const connection = policy.connectionId
          ? (this.get<any[]>("vault:connections") || []).find(
              (item) => item.id === policy.connectionId,
            )
          : null;
        if (policy.connectionId && !connection)
          throw new HttpError(503, "vault_connection_unavailable");
        if (connection && policy.connectionRevision !== connection.revision)
          throw new HttpError(503, "vault_connection_changed");
        return {
          policy,
          vault: connection?.envelope || this.get("vault"),
          connection,
        };
      }
      case "authorize_secret_write": {
        if (!p || p.bootstrap)
          throw new HttpError(401, "customer_session_required");
        const session = this.session(p);
        if (
          session.purpose !== "agent" ||
          !session.scopes.includes("secrets:write")
        )
          throw new HttpError(403, "insufficient_scope");
        const alias = String(c.alias || "");
        const intent = String(c.intent || "");
        if (!session.aliases?.includes(alias))
          throw new HttpError(403, "alias_forbidden");
        const policy = (this.get<SecretPolicy[]>("policies") || []).find(
          (item) => item.alias === alias,
        );
        if (!policy) throw new HttpError(404, "alias_not_found");
        if (
          !session.policyBindings?.[alias] ||
          session.policyBindings[alias] !== JSON.stringify(policy)
        )
          throw new HttpError(403, "grant_policy_changed");
        if (
          (intent !== "create" && intent !== "update" && intent !== "delete") ||
          !policy.secretWrite?.[intent]
        )
          throw new HttpError(403, "secret_write_not_owner_granted");
        const connection = (this.get<any[]>("vault:connections") || []).find(
          (item) => item.id === policy.connectionId,
        );
        if (!connection || connection.revision !== policy.connectionRevision)
          throw new HttpError(409, "vault_connection_changed");
        return { policy, connection };
      }
      case "prepare_private_input": {
        const preparedAt = this.secretSaveNow(c.testNow);
        const retentionExpiresAt = preparedAt + 91 * 86400;
        const session = this.session(p);
        const alias = String(c.alias || "");
        const intent = String(c.intent || "");
        const operationId = String(c.operationId || "");
        const requestId = String(c.requestId || "");
        const target = String(c.target || "");
        const agentIdentity = session.agentId || session.jkt || "";
        if (
          session.purpose !== "agent" ||
          !session.scopes.includes("secrets:write")
        )
          throw new HttpError(403, "insufficient_scope");
        if (!session.aliases?.includes(alias))
          throw new HttpError(403, "alias_forbidden");
        if (
          !/^[A-Za-z0-9_-]{20,128}$/.test(operationId) ||
          !/^[A-Za-z0-9_-]{43}$/.test(requestId) ||
          !["create", "update", "ensure", "delete"].includes(intent) ||
          !agentIdentity
        )
          throw new HttpError(400, "invalid_secret_save_request");
        const policy = (this.get<SecretPolicy[]>("policies") || []).find(
          (item) => item.alias === alias,
        );
        if (
          !policy?.secretWrite?.[
            (intent === "ensure" ? "update" : intent) as
              "create" | "update" | "delete"
          ] ||
          !session.policyBindings?.[alias] ||
          session.policyBindings[alias] !== JSON.stringify(policy)
        )
          throw new HttpError(403, "secret_write_not_owner_granted");
        const connection = (this.get<any[]>("vault:connections") || []).find(
          (item) => item.id === policy.connectionId,
        );
        if (
          !connection ||
          connection.revision !== policy.connectionRevision ||
          !["onepassword-connect", ...COMPANION_WRITE_PROVIDERS].includes(
            connection.provider,
          )
        )
          throw new HttpError(409, "vault_connection_changed");
        if (
          intent === "delete" &&
          companionWriteProvider(connection.provider) &&
          connection.provider !== COMPANION_DELETE_PROVIDER
        )
          throw new HttpError(409, "provider_write_unsupported");
        if (
          !privateInputTargetValid(
            connection.provider,
            intent as "create" | "update" | "ensure" | "delete",
            target,
          )
        )
          throw new HttpError(409, "vault_connection_changed");
        if (!this.companionWritesEnabled(connection.provider))
          throw new HttpError(409, "provider_write_unsupported");
        if (
          (intent === "update" || intent === "ensure" || intent === "delete") &&
          target !== policy.secretId
        )
          throw new HttpError(403, "secret_write_reference_forbidden");
        const binding = JSON.stringify([
          alias,
          operationId,
          agentIdentity,
          JSON.stringify(policy),
          connection.id,
          connection.revision,
          intent,
          target,
        ]);
        const mapKey = "private-input-operation:" + operationId;
        const existingId = this.getAt<string>(mapKey, preparedAt);
        const id = existingId || requestId;
        const key = "private-input:" + id;
        const existing = this.getAt<PrivateInputRequest>(key, preparedAt);
        if (existing) {
          if (existing.binding !== binding)
            throw new HttpError(409, "secret_save_operation_conflict");
          if (
            ["pending", "fulfilling"].includes(existing.status) &&
            existing.expiresAt <= preparedAt
          ) {
            if (existing.status === "fulfilling") {
              this.recoverExpiredPrivateInput(existing, preparedAt);
            } else {
              return { status: "expired", requestId: id };
            }
          }
          return {
            status: existing.status,
            requestId: id,
            ...(existing.reference ? { reference: existing.reference } : {}),
            ...(existing.verified ? { verified: existing.verified } : {}),
            ...(existing.resultStatus
              ? { resultStatus: existing.resultStatus }
              : {}),
          };
        }
        if (existingId)
          throw new HttpError(409, "secret_save_operation_conflict");
        const record: PrivateInputRequest = {
          requestId: id,
          operationId,
          binding,
          agentIdentity,
          alias,
          policyBinding: JSON.stringify(policy),
          connectionId: connection.id,
          revision: connection.revision,
          intent: intent as "create" | "update" | "ensure" | "delete",
          target,
          status: "pending",
          retentionExpiresAt,
          expiresAt: preparedAt + 30 * 60,
          createdAt: preparedAt,
        };
        this.put(mapKey, id, record.retentionExpiresAt);
        this.put(key, record, record.retentionExpiresAt);
        this.put(
          this.privateInputDashboardKey(record),
          this.privateInputDashboardEntry(record),
          record.expiresAt,
        );
        return { status: record.status, requestId: id };
      }
      case "list_private_inputs": {
        this.control(p);
        const listAt = now();
        const cursor = c.cursor === undefined ? "" : String(c.cursor);
        if (
          cursor &&
          !/^private-input-active:(?:\d{12}:)?[A-Za-z0-9_-]{43}$/.test(cursor)
        )
          throw new HttpError(400, "invalid_private_input_cursor");
        const rows = this.storage
          .exec<{ key: string; value: string }>(
            `SELECT key, value FROM records
             WHERE key >= 'private-input-active:'
               AND key < 'private-input-active;'
               AND (? = '' OR key < ?)
               AND (expires IS NULL OR expires > ?)
               AND (
                 json_extract(value, '$.status') IN ('fulfilling', 'unknown')
                 OR (json_extract(value, '$.status') = 'pending'
                     AND CAST(json_extract(value, '$.expiresAt') AS INTEGER) > ?)
               )
             ORDER BY key DESC
             LIMIT 101`,
            cursor,
            cursor,
            listAt,
            listAt,
          )
          .toArray();
        const hasMore = rows.length > 100;
        const page = rows.slice(0, 100);
        return {
          requests: page.map((row) => {
            const entry = JSON.parse(row.value) as PrivateInputDashboardEntry;
            return {
              ...entry,
              status:
                entry.status === "fulfilling" && entry.expiresAt <= listAt
                  ? "unknown"
                  : entry.status,
            };
          }),
          nextCursor: hasMore ? page[page.length - 1].key : null,
        };
      }
      case "claim_private_input": {
        const claimAt = this.secretSaveNow(c.testNow);
        const requestId = String(c.requestId || "");
        if (!/^[A-Za-z0-9_-]{43}$/.test(requestId))
          throw new HttpError(400, "invalid_private_input_request");
        const key = "private-input:" + requestId;
        const request = this.getAt<PrivateInputRequest>(key, claimAt);
        if (!request)
          throw new HttpError(404, "private_input_request_not_found");
        if (p?.purpose === "agent") {
          this.authenticatePrivateInputAgent(
            p,
            request,
            c.executorId,
            c.executorProof,
          );
          if (request.executorId && request.executorId !== c.executorId)
            throw new HttpError(409, "private_input_policy_changed");
        } else {
          this.control(p);
        }
        if (request.status === "unknown") return request;
        if (request.expiresAt <= claimAt) {
          if (request.status === "fulfilling") {
            return this.recoverExpiredPrivateInput(request, claimAt);
          }
          if (request.status === "pending")
            throw new HttpError(404, "private_input_request_not_found");
        }
        if (!["pending", "fulfilling", "saved"].includes(request.status))
          throw new HttpError(409, "private_input_request_not_pending");
        const policy = this.currentPrivateInputPolicy(request);
        const connection = (this.get<any[]>("vault:connections") || []).find(
          (item) => item.id === request.connectionId,
        );
        if (
          !connection ||
          connection.revision !== request.revision ||
          connection.revision !== policy.connectionRevision ||
          !["onepassword-connect", ...COMPANION_WRITE_PROVIDERS].includes(
            connection.provider,
          )
        )
          throw new HttpError(409, "private_input_policy_changed");
        if (!this.companionWritesEnabled(connection.provider))
          throw new HttpError(409, "provider_write_unsupported");
        if (request.status === "pending") {
          request.status = "fulfilling";
          if (p?.purpose === "agent") request.executorId = String(c.executorId);
          this.put(key, request);
          this.put("private-input-operation:" + request.operationId, requestId);
          this.remove("private-input-active:" + requestId);
          this.put(
            this.privateInputDashboardKey(request),
            this.privateInputDashboardEntry(request),
            request.retentionExpiresAt,
          );
          return { ...request, claimed: true };
        }
        return request;
      }
      case "complete_private_input": {
        const completedAt = this.secretSaveNow(c.testNow);
        const requestId = String(c.requestId || "");
        const status = String(c.status || "");
        const reference =
          c.reference === undefined ? undefined : String(c.reference);
        const resultStatus = c.resultStatus;
        if (
          !/^[A-Za-z0-9_-]{43}$/.test(requestId) ||
          !["unknown", "saved", "rejected"].includes(status) ||
          (status === "saved" && (!reference || c.verified !== true))
        )
          throw new HttpError(400, "invalid_private_input_request");
        const key = "private-input:" + requestId;
        const request = this.getAt<PrivateInputRequest>(key, completedAt);
        if (!request)
          throw new HttpError(404, "private_input_request_not_found");
        if (p?.purpose === "agent") {
          this.authenticatePrivateInputAgent(
            p,
            request,
            c.executorId,
            c.executorProof,
          );
          const session = this.session(p);
          if (
            (session.aliases !== undefined &&
              !session.aliases.includes(request.alias)) ||
            !session.policyBindings?.[request.alias] ||
            session.policyBindings[request.alias] !== request.policyBinding
          )
            throw new HttpError(409, "private_input_policy_changed");
          if (
            request.executorId !== c.executorId ||
            request.operationId !== c.operationId
          )
            throw new HttpError(409, "private_input_policy_changed");
        } else {
          this.control(p);
        }
        const policy = this.currentPrivateInputPolicy(request);
        const connection = (this.get<any[]>("vault:connections") || []).find(
          (item) => item.id === request.connectionId,
        );
        if (
          !connection ||
          connection.revision !== request.revision ||
          policy.connectionId !== connection.id ||
          policy.connectionRevision !== connection.revision ||
          !this.companionWritesEnabled(connection.provider) ||
          (status === "saved" &&
            (!reference ||
              !savedReferenceValid(connection.provider, reference)))
        )
          throw new HttpError(400, "invalid_private_input_request");
        if (
          status === "saved" &&
          (request.intent === "ensure"
            ? !["unchanged", "updated"].includes(String(resultStatus))
            : resultStatus !== undefined)
        )
          throw new HttpError(400, "invalid_private_input_request");
        if (
          status === "saved" &&
          request.intent !== "create" &&
          reference !== request.target
        )
          throw new HttpError(409, "secret_save_operation_conflict");
        if (p?.purpose === "agent") {
          const saveKey = "secret-save:" + request.operationId;
          const save = this.getStored<SecretSaveRecord>(saveKey);
          if (
            !save ||
            save.executorId !== c.executorId ||
            save.agentIdentity !== request.agentIdentity ||
            save.alias !== request.alias ||
            save.policyBinding !== request.policyBinding ||
            save.intent !== request.intent ||
            save.connectionId !== request.connectionId ||
            save.revision !== request.revision
          )
            throw new HttpError(409, "private_input_policy_changed");
          if (status === "unknown") {
            if (save.status !== "saved" && save.status !== "unknown") {
              this.put(saveKey, { ...save, status: "unknown" });
              this.releaseSecretSaveLock(
                save.connectionId,
                request.operationId,
              );
            }
          } else if (status === "saved") {
            if (
              save.status === "saved" &&
              (save.reference !== reference ||
                save.resultStatus !== resultStatus)
            )
              throw new HttpError(409, "secret_save_operation_conflict");
            if (save.status === "in_progress") {
              if (
                save.expiresAt <= completedAt ||
                this.get<string>("secret-save-active:" + save.connectionId) !==
                  request.operationId
              ) {
                this.put(saveKey, { ...save, status: "unknown" });
                this.releaseSecretSaveLock(
                  save.connectionId,
                  request.operationId,
                );
                throw new HttpError(409, "secret_save_outcome_unknown");
              }
              this.put(saveKey, {
                ...save,
                status: "saved",
                reference,
                verified: true,
                ...(resultStatus ? { resultStatus } : {}),
              });
              this.releaseSecretSaveLock(
                save.connectionId,
                request.operationId,
              );
            } else if (save.status !== "saved") {
              throw new HttpError(409, "secret_save_outcome_unknown");
            }
          }
        }
        if (request.status === "saved") {
          if (
            request.reference !== reference ||
            request.resultStatus !== resultStatus
          )
            throw new HttpError(409, "secret_save_operation_conflict");
          return {
            status: request.status,
            reference,
            verified: true,
            ...(request.resultStatus
              ? { resultStatus: request.resultStatus }
              : {}),
          };
        }
        if (request.status !== "fulfilling" && status !== "rejected")
          throw new HttpError(409, "private_input_request_not_pending");
        request.status = status as PrivateInputRequest["status"];
        if (reference) request.reference = reference;
        if (c.verified === true) request.verified = true;
        if (resultStatus)
          request.resultStatus = resultStatus as "unchanged" | "updated";
        request.expiresAt = completedAt + 91 * 86400;
        delete request.retentionExpiresAt;
        this.put(key, request);
        this.put("private-input-operation:" + request.operationId, requestId);
        this.remove("private-input-active:" + requestId);
        if (request.status === "unknown")
          this.put(
            this.privateInputDashboardKey(request),
            this.privateInputDashboardEntry(request),
          );
        else this.remove(this.privateInputDashboardKey(request));
        return {
          status: request.status,
          ...(request.reference ? { reference: request.reference } : {}),
          ...(request.verified ? { verified: request.verified } : {}),
          ...(request.resultStatus
            ? { resultStatus: request.resultStatus }
            : {}),
        };
      }
      case "save_policy": {
        this.control(p);
        const policy = c.policy as SecretPolicy;
        if (
          p.tenant !== "default" &&
          (!policy.connectionId || !policy.secretId)
        )
          throw new HttpError(400, "vault_connection_and_secret_required");
        let saved = policy;
        if (policy.connectionId) {
          const connection = (this.get<any[]>("vault:connections") || []).find(
            (item) => item.id === policy.connectionId,
          );
          if (!connection)
            throw new HttpError(400, "vault_connection_not_owned");
          if (
            policy.secretWrite &&
            !["onepassword-connect", ...COMPANION_WRITE_PROVIDERS].includes(
              connection.provider,
            )
          )
            throw new HttpError(409, "provider_write_unsupported");
          if (
            policy.secretWrite &&
            !this.companionWritesEnabled(connection.provider)
          )
            throw new HttpError(409, "provider_write_unsupported");
          if (
            policy.secretWrite?.delete &&
            companionWriteProvider(connection.provider) !== null &&
            connection.provider !== COMPANION_DELETE_PROVIDER
          )
            throw new HttpError(409, "provider_write_unsupported");
          saved = { ...policy, connectionRevision: connection.revision };
        }
        this.put("policies", [
          ...(this.get<SecretPolicy[]>("policies") || []).filter(
            (item) => item.alias !== policy.alias,
          ),
          saved,
        ]);
        return true;
      }
      case "update_policy_find_selector": {
        this.control(p);
        const policies = this.get<SecretPolicy[]>("policies") || [];
        const index = policies.findIndex((item) => item.alias === c.alias);
        if (index < 0) throw new HttpError(404, "policy_not_found");
        const current = policies[index];
        if (
          current.connectionId !== c.expectedConnectionId ||
          current.connectionRevision !== c.expectedConnectionRevision ||
          current.secretId !== c.expectedSecretId
        )
          throw new HttpError(409, "policy_changed_retry");
        const connections =
          this.get<VaultConnection[]>("vault:connections") || [];
        const connection = connections.find(
          (item) => item.id === current.connectionId,
        );
        if (
          !connection ||
          connection.revision !== current.connectionRevision ||
          connection.provider !== "onepassword-connect"
        )
          throw new HttpError(409, "provider_selector_unsupported");
        const findSelector = c.findSelector as
          SecretPolicy["findSelector"] | undefined;
        if (findSelector) {
          if (typeof current.secretId !== "string")
            throw new HttpError(409, "explicit_secret_reference_required");
          const parts = current.secretId.split("#");
          let fieldId = "";
          try {
            if (parts.length === 2) fieldId = decodeURIComponent(parts[1]);
          } catch {
            fieldId = "";
          }
          if (
            !fieldId ||
            findSelector.kind !== "login_lookup" ||
            findSelector.fieldId !== fieldId
          )
            throw new HttpError(400, "invalid_policy_find_selector");
        }
        const next = { ...current } as SecretPolicy;
        if (findSelector) next.findSelector = findSelector;
        else delete next.findSelector;
        policies[index] = next;
        this.put("policies", policies);
        return true;
      }
      case "delete_policy":
        this.control(p);
        this.put(
          "policies",
          (this.get<SecretPolicy[]>("policies") || []).filter(
            (item) => item.alias !== c.alias,
          ),
        );
        return true;
      case "enroll_executor": {
        this.control(p);
        const executor = c.executor as {
          executorId?: unknown;
          thumbprint?: unknown;
          publicJwk?: unknown;
          createdAt?: unknown;
        };
        if (
          !executor ||
          typeof executor.executorId !== "string" ||
          !executor.executorId.startsWith("exe_") ||
          typeof executor.thumbprint !== "string" ||
          !executor.publicJwk
        )
          throw new HttpError(400, "invalid_executor_identity");
        const registered =
          this.get<Array<Record<string, unknown>>>("executors") || [];
        const existing = registered.find(
          (item) => item.executorId === executor.executorId,
        );
        if (existing) {
          if (existing.thumbprint !== executor.thumbprint)
            throw new HttpError(409, "executor_conflict");
          return { executorId: executor.executorId, status: "enrolled" };
        }
        if (registered.length >= 10)
          throw new HttpError(409, "executor_limit_reached");
        const enrolledAt = now();
        this.put("executors", [
          ...registered,
          {
            executorId: executor.executorId,
            thumbprint: executor.thumbprint,
            publicJwk: executor.publicJwk,
            createdAt: Number.isSafeInteger(executor.createdAt)
              ? executor.createdAt
              : enrolledAt,
            enrolledAt,
          },
        ]);
        return { executorId: executor.executorId, status: "enrolled" };
      }
      case "list_executors": {
        this.control(p);
        return (
          this.get<Array<Record<string, unknown>>>("executors") || []
        ).map((executor) => ({
          executorId: executor.executorId,
          thumbprint: executor.thumbprint,
          publicJwk: executor.publicJwk,
          createdAt: executor.createdAt,
          enrolledAt: executor.enrolledAt,
        }));
      }
      case "issue_browser_grant": {
        const session = this.control(p);
        const request = c.grant as BrowserGrantIssue;
        if (
          !request ||
          typeof request.executorId !== "string" ||
          typeof request.alias !== "string" ||
          typeof request.fieldSelector !== "string" ||
          request.fieldSelector.length === 0 ||
          request.fieldSelector.length > 1024 ||
          !Number.isSafeInteger(request.expiresAt) ||
          request.expiresAt <= now() + 4 ||
          request.expiresAt > now() + 300 ||
          !Array.isArray(request.kinds) ||
          request.kinds.length === 0
        )
          throw new HttpError(400, "invalid_browser_grant");
        const executor = (
          this.get<Array<Record<string, unknown>>>("executors") || []
        ).find((item) => item.executorId === request.executorId);
        if (!executor || typeof executor.thumbprint !== "string")
          throw new HttpError(404, "executor_not_found");
        const policy = (this.get<SecretPolicy[]>("policies") || []).find(
          (item) => item.alias === request.alias,
        );
        if (!policy) throw new HttpError(404, "alias_not_found");
        if (
          request.kinds.some(
            (kind) => kind === "capture" || kind === "ensure",
          ) &&
          !policy.secretWrite?.update
        )
          throw new HttpError(403, "browser_grant_write_denied");
        if (!browserGrantOriginAllowed(request.origin, policy.allowedDomains))
          throw new HttpError(403, "browser_grant_origin_denied");
        const activeGrantCount = this.storage
          .exec<{ count: number }>(
            "SELECT COUNT(*) AS count FROM records WHERE key LIKE 'browser-grant:%' AND expires > ?",
            now(),
          )
          .toArray()[0]?.count;
        if ((activeGrantCount || 0) >= 100)
          throw new HttpError(409, "browser_grant_limit_reached");
        const grantId = reference("bg1", session.tenant);
        const grant: BrowserGrantRecord = {
          grantId,
          accountId: session.tenant,
          executorId: request.executorId,
          executorThumbprint: executor.thumbprint,
          alias: request.alias,
          origin: browserGrantOrigin(request.origin),
          kinds: [...request.kinds],
          fieldSelector: request.fieldSelector,
          policyBinding: JSON.stringify(policy),
          epoch: this.epoch(),
          expiresAt: request.expiresAt,
          redeemedAt: null,
          revokedAt: null,
        };
        this.put("browser-grant:" + grantId, grant, grant.expiresAt + 3600);
        return browserGrantView(grant);
      }
      case "redeem_browser_grant": {
        const action = c.action as BrowserGrantAction;
        const proof = c.proof as Proof;
        const tenant = browserGrantTenant(action?.grantId);
        if (tenant !== c.tenant)
          throw new HttpError(400, "invalid_browser_grant");
        const stored = this.getStored<BrowserGrantRecord>(
          "browser-grant:" + action.grantId,
        );
        if (!stored) throw new HttpError(404, "browser_grant_unknown");
        if (
          stored.accountId !== action.accountId ||
          tenant !== action.accountId
        )
          throw new HttpError(403, "browser_grant_account_mismatch");
        if (stored.revokedAt !== null || stored.epoch !== this.epoch())
          throw new HttpError(403, "browser_grant_revoked");
        if (stored.redeemedAt !== null)
          throw new HttpError(409, "browser_grant_replayed");
        if (stored.expiresAt <= now())
          throw new HttpError(410, "browser_grant_expired");
        if (browserGrantOrigin(action.origin) !== stored.origin)
          throw new HttpError(403, "browser_grant_origin_mismatch");
        if (!stored.kinds.includes(action.kind as BrowserActionKind))
          throw new HttpError(403, "browser_grant_action_denied");
        if (stored.fieldSelector !== action.fieldSelector)
          throw new HttpError(403, "browser_grant_field_mismatch");
        const executor = (
          this.get<Array<Record<string, unknown>>>("executors") || []
        ).find((item) => item.executorId === stored.executorId);
        if (
          !executor ||
          executor.thumbprint !== stored.executorThumbprint ||
          !proof ||
          proof.jkt !== stored.executorThumbprint
        )
          throw new HttpError(403, "browser_grant_executor_mismatch");
        const policy = (this.get<SecretPolicy[]>("policies") || []).find(
          (item) => item.alias === stored.alias,
        );
        if (!policy || JSON.stringify(policy) !== stored.policyBinding)
          throw new HttpError(409, "browser_grant_policy_changed");
        if (!browserGrantOriginAllowed(stored.origin, policy.allowedDomains))
          throw new HttpError(403, "browser_grant_origin_denied");
        this.replay(proof);
        const usageKey = "usage:" + new Date().toISOString().slice(0, 7);
        const used = this.get<number>(usageKey) || 0;
        if (used >= this.limit()) throw new HttpError(429, "quota_exceeded");
        this.put(usageKey, used + 1, now() + 70 * 86400);
        const redeemed: BrowserGrantRecord = {
          ...stored,
          redeemedAt: now(),
        };
        this.put(
          "browser-grant:" + stored.grantId,
          redeemed,
          stored.expiresAt + 3600,
        );
        return browserGrantReceipt(redeemed, action.kind);
      }
      case "list_browser_grants": {
        const session = this.control(p);
        const at = now();
        return this.storage
          .exec<{ value: string }>(
            "SELECT value FROM records WHERE key LIKE 'browser-grant:%' AND expires > ? ORDER BY key DESC LIMIT 100",
            at,
          )
          .toArray()
          .map((row) => JSON.parse(row.value) as BrowserGrantRecord)
          .filter((grant) => grant.accountId === session.tenant)
          .map(browserGrantView);
      }
      case "revoke_browser_grant": {
        const session = this.control(p);
        const grantId = browserGrantTenant(String(c.grantId || ""));
        if (grantId !== session.tenant)
          throw new HttpError(403, "browser_grant_account_mismatch");
        const key = "browser-grant:" + String(c.grantId);
        const stored = this.getStored<BrowserGrantRecord>(key);
        if (!stored) throw new HttpError(404, "browser_grant_unknown");
        this.put(
          key,
          {
            ...stored,
            revokedAt: stored.revokedAt ?? now(),
          } satisfies BrowserGrantRecord,
          stored.expiresAt + 3600,
        );
        return { grantId: String(c.grantId), revoked: true };
      }
      case "revoke_executor": {
        const session = this.control(p);
        const executorId = String(c.executorId || "");
        if (!/^exe_[A-Za-z0-9_-]{43}$/u.test(executorId))
          throw new HttpError(400, "invalid_executor_identity");
        const registered =
          this.get<Array<Record<string, unknown>>>("executors") || [];
        const executor = registered.find(
          (item) => item.executorId === executorId,
        );
        if (!executor) throw new HttpError(404, "executor_not_found");
        this.put(
          "executors",
          registered.filter((item) => item.executorId !== executorId),
        );
        const revokedAt = now();
        for (const row of this.storage
          .exec<{ key: string; value: string }>(
            "SELECT key, value FROM records WHERE key LIKE 'browser-grant:%' AND expires > ?",
            revokedAt,
          )
          .toArray()) {
          const grant = JSON.parse(row.value) as BrowserGrantRecord;
          if (
            grant.accountId === session.tenant &&
            grant.executorId === executorId &&
            grant.revokedAt === null
          )
            this.put(
              row.key,
              { ...grant, revokedAt } satisfies BrowserGrantRecord,
              grant.expiresAt + 3600,
            );
        }
        return { executorId, revoked: true };
      }
      case "save_vault":
        this.control(p);
        this.put("vault", c.envelope);
        this.put(
          "policies",
          (this.get<SecretPolicy[]>("policies") || []).map((item) =>
            item.connectionId
              ? item
              : { ...item, connectionId: "disconnected" },
          ),
        );
        return true;
      case "vault":
        this.control(p);
        return this.get("vault");
      case "connections":
        this.control(p);
        return this.get("vault:connections") || [];
      case "save_connection": {
        this.control(p);
        const connections = this.get<any[]>("vault:connections") || [];
        const next = c.connection as any;
        const previous = connections.find((item) => item.id === next.id);
        this.retireExpiredSecretSaveLock(
          String(next.id),
          this.secretSaveNow(c.testNow),
        );
        if (previous && this.get("secret-save-active:" + next.id))
          throw new HttpError(409, "secret_save_in_progress");
        if (previous && next.revision !== previous.revision + 1)
          throw new HttpError(409, "vault_connection_revision_conflict");
        if (!previous && next.revision !== 1)
          throw new HttpError(409, "vault_connection_revision_conflict");
        if (
          connections.some(
            (item) => item.alias === next.alias && item.id !== next.id,
          )
        )
          throw new HttpError(409, "vault_connection_alias_exists");
        this.put("vault:connections", [
          ...connections.filter((item) => item.id !== next.id),
          next,
        ]);
        return true;
      }
      case "delete_connection": {
        this.control(p);
        const connections = this.get<any[]>("vault:connections") || [];
        if (!connections.some((item) => item.id === c.id))
          throw new HttpError(404, "vault_connection_not_found");
        this.retireExpiredSecretSaveLock(
          String(c.id),
          this.secretSaveNow(c.testNow),
        );
        if (this.get("secret-save-active:" + String(c.id)))
          throw new HttpError(409, "secret_save_in_progress");
        this.put(
          "vault:connections",
          connections.filter((item) => item.id !== c.id),
        );
        this.put(
          "policies",
          (this.get<SecretPolicy[]>("policies") || []).map((item) =>
            item.connectionId === c.id
              ? { ...item, connectionId: "disconnected" }
              : item,
          ),
        );
        return true;
      }
      case "rekey_connections": {
        this.control(p);
        const connections = this.get<any[]>("vault:connections") || [];
        const replacements = c.connections as any[];
        if (
          !Array.isArray(replacements) ||
          replacements.length !== connections.length
        )
          throw new HttpError(409, "vault_connection_set_changed");
        for (const replacement of replacements) {
          const current = connections.find(
            (item) => item.id === replacement.id,
          );
          if (
            !current ||
            current.revision !== replacement.expectedRevision ||
            replacement.connection.revision !== current.revision + 1
          )
            throw new HttpError(409, "vault_connection_revision_conflict");
          this.retireExpiredSecretSaveLock(
            String(replacement.id),
            this.secretSaveNow(c.testNow),
          );
          if (this.get("secret-save-active:" + replacement.id))
            throw new HttpError(409, "secret_save_in_progress");
        }
        const updated = replacements.map((item) => item.connection);
        this.put("vault:connections", updated);
        const revisions = new Map(
          updated.map((item) => [item.id, item.revision]),
        );
        const previousRevisions = new Map(
          connections.map((item) => [item.id, item.revision]),
        );
        this.put(
          "policies",
          (this.get<SecretPolicy[]>("policies") || []).map((item) => {
            const revision = item.connectionId
              ? revisions.get(item.connectionId)
              : undefined;
            const previousRevision = item.connectionId
              ? previousRevisions.get(item.connectionId)
              : undefined;
            return revision && item.connectionRevision === previousRevision
              ? { ...item, connectionRevision: revision }
              : item;
          }),
        );
        return true;
      }
      case "account": {
        this.session(p);
        return {
          plan: "self-hosted",
          currentUsage:
            this.get<number>("usage:" + new Date().toISOString().slice(0, 7)) ||
            0,
          monthlyAllowance: this.limit(),
        };
      }
      case "reserve_secret_save": {
        const agentHash = p?.purpose === "agent" ? p.hash : undefined;
        const alias = agentHash ? String(c.alias || "") : undefined;
        let agentIdentity: string | undefined;
        let policyBinding: string | undefined;
        if (!agentHash) this.control(p);
        else {
          const session = this.session(p);
          agentIdentity = session.agentId || session.jkt;
          if (
            !session.scopes.includes("secrets:write") ||
            !session.aliases?.includes(alias!) ||
            !agentIdentity
          )
            throw new HttpError(403, "insufficient_scope");
          const policy = (this.get<SecretPolicy[]>("policies") || []).find(
            (item) => item.alias === alias,
          );
          if (
            !policy ||
            !["create", "update", "delete", "ensure"].includes(
              String(c.intent || "create"),
            ) ||
            !policy.secretWrite?.[
              (String(c.intent || "create") === "ensure"
                ? "update"
                : String(c.intent || "create")) as
                "create" | "update" | "delete"
            ] ||
            !session.policyBindings?.[alias!] ||
            session.policyBindings[alias!] !== JSON.stringify(policy) ||
            policy.connectionId !== c.connectionId ||
            ((c.intent === "update" ||
              c.intent === "ensure" ||
              c.intent === "delete") &&
              policy.secretId !== c.title)
          )
            throw new HttpError(403, "secret_write_not_owner_granted");
          policyBinding = JSON.stringify(policy);
        }
        const operationNow = this.secretSaveNow(c.testNow);
        const operationId = String(c.operationId || "");
        const connectionId = String(c.connectionId || "");
        const revision = Number(c.revision);
        const intent = (
          c.intent === undefined ? "create" : String(c.intent)
        ) as "create" | "update" | "delete" | "ensure";
        const targetInput = String(c.title || "");
        const title = intent === "create" ? targetInput.trim() : targetInput;
        const payloadDigest =
          c.payloadDigest === undefined ? undefined : String(c.payloadDigest);
        const privateInputRequestId =
          c.privateInputRequestId === undefined
            ? undefined
            : String(c.privateInputRequestId);
        const commandConnection = (
          this.get<any[]>("vault:connections") || []
        ).find((item) => item.id === connectionId);
        if (
          commandConnection &&
          !this.companionWritesEnabled(commandConnection.provider)
        )
          throw new HttpError(409, "provider_write_unsupported");
        if (
          commandConnection &&
          intent === "delete" &&
          companionWriteProvider(commandConnection.provider) &&
          commandConnection.provider !== COMPANION_DELETE_PROVIDER
        )
          throw new HttpError(409, "provider_write_unsupported");
        if (
          !/^[A-Za-z0-9_-]{20,128}$/.test(operationId) ||
          !/^[A-Za-z0-9_-]{16,128}$/.test(connectionId) ||
          !Number.isSafeInteger(revision) ||
          revision < 1 ||
          !["create", "update", "delete", "ensure"].includes(intent) ||
          (intent === "ensure" && payloadDigest === undefined) ||
          (intent === "delete" && payloadDigest !== undefined) ||
          !title ||
          !privateInputTargetValid(
            String(commandConnection?.provider || ""),
            intent,
            title,
          ) ||
          (payloadDigest !== undefined &&
            !/^[A-Za-z0-9_-]{43}$/.test(payloadDigest)) ||
          (privateInputRequestId !== undefined &&
            !/^[A-Za-z0-9_-]{43}$/.test(privateInputRequestId))
        )
          throw new HttpError(400, "invalid_secret_save_request");
        if (privateInputRequestId) {
          const ticket = this.getAt<PrivateInputRequest>(
            "private-input:" + privateInputRequestId,
            operationNow,
          );
          const ticketConnection = ticket
            ? (this.get<any[]>("vault:connections") || []).find(
                (item) => item.id === ticket.connectionId,
              )
            : undefined;
          if (
            p?.purpose === "agent" &&
            ticket &&
            (ticket.executorId !== undefined ||
              ticketConnection?.provider === "onepassword-service-account")
          ) {
            this.authenticatePrivateInputAgent(
              p,
              ticket,
              c.executorId,
              c.executorProof,
            );
          }
          const currentPolicy = ticket
            ? (this.get<SecretPolicy[]>("policies") || []).find(
                (item) => item.alias === ticket.alias,
              )
            : undefined;
          const currentConnection = ticket
            ? (this.get<any[]>("vault:connections") || []).find(
                (item) => item.id === ticket.connectionId,
              )
            : undefined;
          const ticketTarget = ticket
            ? ticket.intent === "create"
              ? ticket.target.trim()
              : ticket.target
            : "";
          if (
            !ticket ||
            !["fulfilling", "saved"].includes(ticket.status) ||
            (ticket.status === "fulfilling" &&
              ticket.expiresAt <= operationNow) ||
            ticket.operationId !== operationId ||
            ticket.connectionId !== connectionId ||
            ticket.revision !== revision ||
            ticket.intent !== intent ||
            ticketTarget !== title ||
            !currentPolicy ||
            JSON.stringify(currentPolicy) !== ticket.policyBinding ||
            !currentPolicy.secretWrite?.[
              intent === "ensure" ? "update" : intent
            ] ||
            ((intent === "update" || intent === "ensure") &&
              currentPolicy.secretId !== title) ||
            !currentConnection ||
            currentConnection.revision !== revision ||
            currentConnection.id !== currentPolicy.connectionId ||
            !["onepassword-connect", ...COMPANION_WRITE_PROVIDERS].includes(
              currentConnection.provider,
            ) ||
            currentPolicy.connectionRevision !== revision ||
            (p?.purpose === "agent" &&
              (ticket.executorId !== c.executorId ||
                !privateInputTargetValid(
                  currentConnection.provider,
                  ticket.intent,
                  title,
                )))
          )
            throw new HttpError(409, "private_input_policy_changed");
        }
        if (
          p?.purpose === "agent" &&
          c.executorId !== undefined &&
          !privateInputRequestId
        )
          this.authenticateTrustedExecutor(p, c.executorId, c.executorProof);
        const binding = JSON.stringify(
          agentHash
            ? payloadDigest === undefined
              ? [connectionId, revision, title, intent, agentIdentity, alias]
              : [
                  connectionId,
                  revision,
                  title,
                  intent,
                  payloadDigest,
                  agentIdentity,
                  alias,
                ]
            : payloadDigest === undefined
              ? [connectionId, revision, title, intent]
              : [connectionId, revision, title, intent, payloadDigest],
        );
        const operationBinding = privateInputRequestId
          ? JSON.stringify([binding, privateInputRequestId])
          : binding;
        const key = "secret-save:" + operationId;
        const existing = this.getStored<SecretSaveRecord>(key);
        if (existing) {
          const legacyCreateBinding = JSON.stringify([
            connectionId,
            revision,
            title,
            "create",
          ]);
          const legacyCreateReplay =
            !privateInputRequestId &&
            payloadDigest !== undefined &&
            intent === "create" &&
            existing.binding === legacyCreateBinding;
          if (existing.binding !== operationBinding && !legacyCreateReplay)
            throw new HttpError(409, "secret_save_operation_conflict");
          if (
            existing.status === "in_progress" &&
            existing.expiresAt <= operationNow
          ) {
            this.put(key, { ...existing, status: "unknown" });
            this.releaseSecretSaveLock(connectionId, operationId);
            return { status: "unknown" };
          }
          return {
            status: existing.status,
            ...(legacyCreateReplay ? { legacyBinding: true } : {}),
            ...(existing.reference ? { reference: existing.reference } : {}),
            ...(existing.verified ? { verified: existing.verified } : {}),
            ...(existing.resultStatus
              ? { resultStatus: existing.resultStatus }
              : {}),
          };
        }
        const connection = (this.get<any[]>("vault:connections") || []).find(
          (item) => item.id === connectionId,
        );
        if (!connection) throw new HttpError(404, "vault_connection_not_found");
        if (connection.revision !== revision)
          throw new HttpError(409, "vault_connection_changed");
        const activeKey = "secret-save-active:" + connectionId;
        const activeId = this.get<string>(activeKey);
        if (activeId) {
          const activeOperation = this.getStored<SecretSaveRecord>(
            "secret-save:" + activeId,
          );
          if (
            activeOperation?.status === "in_progress" &&
            activeOperation.expiresAt <= operationNow
          ) {
            this.put("secret-save:" + activeId, {
              ...activeOperation,
              status: "unknown",
            });
            this.releaseSecretSaveLock(connectionId, activeId);
          } else {
            throw new HttpError(409, "secret_save_in_progress");
          }
        }
        const quotaKey =
          "usage:" + new Date(operationNow * 1000).toISOString().slice(0, 7);
        const used = this.get<number>(quotaKey) || 0;
        if (used >= this.limit()) throw new HttpError(429, "quota_exceeded");
        this.put(quotaKey, used + 1, operationNow + 70 * 86400);
        this.put(key, {
          binding: operationBinding,
          connectionId,
          revision,
          ...(agentHash
            ? { agentHash, agentIdentity, alias, policyBinding }
            : {}),
          intent,
          target: title,
          ...(typeof c.executorId === "string"
            ? { executorId: c.executorId }
            : {}),
          expiresAt: operationNow + 120,
          status: "in_progress",
        } satisfies SecretSaveRecord);
        this.put("secret-save-active:" + connectionId, operationId);
        return { status: "reserved" };
      }
      case "complete_secret_save": {
        if (p?.purpose !== "agent") this.control(p);
        const operationNow = this.secretSaveNow(c.testNow);
        const operationId = String(c.operationId || "");
        if (!/^[A-Za-z0-9_-]{20,128}$/.test(operationId))
          throw new HttpError(400, "invalid_secret_save_request");
        const key = "secret-save:" + operationId;
        const existing = this.getStored<SecretSaveRecord>(key);
        if (!existing)
          throw new HttpError(404, "secret_save_operation_not_found");
        if (existing.agentHash) {
          const session = this.session(p);
          const currentPolicy = (
            this.get<SecretPolicy[]>("policies") || []
          ).find((item) => item.alias === existing.alias);
          if (
            (existing.agentIdentity
              ? (session.agentId || session.jkt) !== existing.agentIdentity
              : p.hash !== existing.agentHash) ||
            !session.scopes.includes("secrets:write") ||
            !currentPolicy ||
            JSON.stringify(currentPolicy) !== existing.policyBinding ||
            !session.policyBindings?.[existing.alias!] ||
            session.policyBindings[existing.alias!] !==
              existing.policyBinding ||
            !currentPolicy.secretWrite?.[
              existing.intent === "ensure"
                ? "update"
                : existing.intent || "create"
            ]
          )
            throw new HttpError(403, "grant_policy_changed");
        }
        const status = c.status;
        if (existing.executorId && existing.executorId !== c.executorId)
          throw new HttpError(403, "trusted_executor_required");
        if (existing.executorId)
          this.authenticateTrustedExecutor(p, c.executorId, c.executorProof);
        if (status === "unknown") {
          if (existing.status === "saved")
            return {
              status: existing.status,
              reference: existing.reference,
              verified: existing.verified,
            };
          if (existing.status !== "unknown") {
            this.put(key, { ...existing, status });
            this.releaseSecretSaveLock(existing.connectionId, operationId);
            return { status };
          }
          return { status: existing.status };
        }
        if (status === "failed") {
          if (existing.intent !== "ensure")
            throw new HttpError(400, "invalid_secret_save_result");
          if (existing.status === "saved")
            throw new HttpError(409, "secret_save_operation_conflict");
          if (existing.status !== "in_progress")
            return { status: existing.status };
          this.put(key, { ...existing, status: "failed" });
          this.releaseSecretSaveLock(existing.connectionId, operationId);
          return { status: "failed" };
        }
        const reference = String(c.reference || "");
        const resultStatus = c.resultStatus;
        if (
          existing.intent !== undefined &&
          existing.intent !== "create" &&
          existing.target !== undefined &&
          existing.target !== reference
        )
          throw new HttpError(409, "secret_save_operation_conflict");
        const completionConnection = (
          this.get<any[]>("vault:connections") || []
        ).find((item) => item.id === existing.connectionId);
        if (
          status !== "saved" ||
          !completionConnection ||
          !this.companionWritesEnabled(completionConnection.provider) ||
          !savedReferenceValid(completionConnection.provider, reference) ||
          c.verified !== true ||
          (existing.intent === "ensure"
            ? !["unchanged", "updated"].includes(String(resultStatus))
            : resultStatus !== undefined)
        )
          throw new HttpError(400, "invalid_secret_save_result");
        if (existing.status === "saved") {
          if (
            existing.reference !== reference ||
            existing.resultStatus !== resultStatus
          )
            throw new HttpError(409, "secret_save_operation_conflict");
          return {
            status: existing.status,
            reference,
            verified: true,
            ...(existing.resultStatus
              ? { resultStatus: existing.resultStatus }
              : {}),
          };
        }
        if (existing.status !== "in_progress")
          throw new HttpError(409, "secret_save_outcome_unknown");
        if (existing.expiresAt <= operationNow) {
          this.put(key, { ...existing, status: "unknown" });
          this.releaseSecretSaveLock(existing.connectionId, operationId);
          throw new HttpError(409, "secret_save_outcome_unknown");
        }
        const connection = (this.get<any[]>("vault:connections") || []).find(
          (item) => item.id === existing.connectionId,
        );
        if (
          !connection ||
          connection.revision !== existing.revision ||
          this.get<string>("secret-save-active:" + existing.connectionId) !==
            operationId
        ) {
          this.put(key, { ...existing, status: "unknown" });
          this.releaseSecretSaveLock(existing.connectionId, operationId);
          throw new HttpError(409, "secret_save_outcome_unknown");
        }
        this.put(key, {
          ...existing,
          status: "saved",
          reference,
          verified: true,
          ...(resultStatus ? { resultStatus } : {}),
        });
        this.releaseSecretSaveLock(existing.connectionId, operationId);
        return {
          status: "saved",
          reference,
          verified: true,
          ...(resultStatus ? { resultStatus } : {}),
        };
      }
      case "audit":
        this.control(p);
        return this.storage
          .exec<{ value: string }>(
            "SELECT value FROM records WHERE key LIKE 'audit:%' ORDER BY key DESC LIMIT 50",
          )
          .toArray()
          .map((row) => JSON.parse(row.value));
      case "record_audit":
        this.put(
          "audit:" + Date.now() + ":" + String(c.id),
          c.event,
          now() + 604800,
        );
        return true;
      case "execute": {
        const session = this.session(p);
        if (
          !session.scopes.includes("secrets:proxy") &&
          !session.scopes.includes("admin")
        )
          throw new HttpError(403, "insufficient_scope");
        if (
          session.aliases !== undefined &&
          !session.aliases.includes(String(c.alias))
        )
          throw new HttpError(403, "alias_forbidden");
        const policy = (this.get<SecretPolicy[]>("policies") || []).find(
          (item) => item.alias === c.alias,
        );
        if (!policy) throw new HttpError(404, "alias_not_found");
        if (
          session.purpose === "agent" &&
          (!session.policyBindings?.[String(c.alias)] ||
            session.policyBindings[String(c.alias)] !== JSON.stringify(policy))
        )
          throw new HttpError(
            403,
            session.policyBindings
              ? "grant_policy_changed"
              : "grant_policy_binding_missing",
          );
        if (
          !validateRequestPolicy(policy, String(c.url), String(c.method))
            .isValid
        )
          throw new HttpError(403, "policy_denied");
        const connection = policy.connectionId
          ? (this.get<any[]>("vault:connections") || []).find(
              (item) => item.id === policy.connectionId,
            )
          : null;
        if (p.tenant !== "default" && !policy.connectionId)
          throw new HttpError(503, "vault_connection_required");
        if (policy.connectionId && !connection)
          throw new HttpError(503, "vault_connection_unavailable");
        if (connection && policy.connectionRevision !== connection.revision)
          throw new HttpError(503, "vault_connection_changed");
        if (session.purpose === "agent") {
          if (
            !session.policyBindings ||
            (session.aliases || []).some(
              (alias) => !session.policyBindings?.[alias],
            )
          )
            throw new HttpError(403, "grant_policy_binding_missing");
          const proof = c.proof as Proof;
          if (
            !proof ||
            proof.jkt !== session.jkt ||
            proof.requestHash !== c.requestHash
          )
            throw new HttpError(401, "invalid_dpop_proof");
          this.replay(proof);
        }
        const key = "usage:" + new Date().toISOString().slice(0, 7);
        const used = this.get<number>(key) || 0;
        if (used >= this.limit()) throw new HttpError(429, "quota_exceeded");
        this.put(key, used + 1, now() + 70 * 86400);
        return {
          policy,
          vault: connection?.envelope || this.get("vault"),
          connection,
        };
      }
      case "create_proxy_capability": {
        const session = this.session(p);
        if (
          session.purpose !== "agent" ||
          !session.scopes.includes("secrets:proxy") ||
          !p.jkt ||
          !c.proof ||
          (c.proof as Proof).jkt !== session.jkt ||
          (c.proof as Proof).requestHash !== c.requestHash
        )
          throw new HttpError(403, "proxy_capability_forbidden");
        const alias = String(c.alias);
        if (session.aliases !== undefined && !session.aliases.includes(alias))
          throw new HttpError(403, "alias_forbidden");
        const policy = (this.get<SecretPolicy[]>("policies") || []).find(
          (item) => item.alias === alias,
        );
        if (!policy) throw new HttpError(404, "alias_not_found");
        if (
          !session.policyBindings ||
          session.policyBindings[alias] !== JSON.stringify(policy)
        )
          throw new HttpError(403, "grant_policy_changed");
        const url = String(c.url);
        const method = String(c.method);
        if (!validateRequestPolicy(policy, url, method).isValid)
          throw new HttpError(403, "policy_denied");
        const connection = policy.connectionId
          ? (this.get<any[]>("vault:connections") || []).find(
              (item) => item.id === policy.connectionId,
            )
          : null;
        if (p.tenant !== "default" && !policy.connectionId)
          throw new HttpError(503, "vault_connection_required");
        if (policy.connectionId && !connection)
          throw new HttpError(503, "vault_connection_unavailable");
        if (connection && policy.connectionRevision !== connection.revision)
          throw new HttpError(503, "vault_connection_changed");
        const activeCapabilities =
          this.storage
            .exec<{ count: number }>(
              "SELECT COUNT(*) AS count FROM records WHERE key LIKE 'proxy-capability:%' AND expires > ?",
              now(),
            )
            .toArray()[0]?.count || 0;
        if (activeCapabilities >= 100)
          throw new HttpError(429, "proxy_capability_limit");
        this.replay(c.proof as Proof);
        const expiresAt = now() + 60;
        this.put(
          "proxy-capability:" + String(c.capabilityHash),
          {
            requestDigest: String(c.requestDigest),
            sessionHash: p.hash,
            agentId: session.agentId,
            jkt: session.jkt,
            alias,
            policyBinding: JSON.stringify(policy),
            connectionId: policy.connectionId,
            connectionRevision: policy.connectionRevision,
            url,
            method,
            expiresAt,
          } satisfies ProxyCapabilityRecord,
          expiresAt,
        );
        return { expiresAt };
      }
      case "revoke_proxy_capability": {
        const session = this.session(p);
        if (
          session.purpose !== "agent" ||
          !session.scopes.includes("secrets:proxy") ||
          !p.jkt ||
          !c.proof ||
          (c.proof as Proof).jkt !== session.jkt ||
          (c.proof as Proof).requestHash !== c.requestHash
        )
          throw new HttpError(403, "proxy_capability_forbidden");
        this.replay(c.proof as Proof);
        const key = "proxy-capability:" + String(c.capabilityHash);
        const capability = this.get<ProxyCapabilityRecord>(key);
        if (
          !capability ||
          capability.expiresAt <= now() ||
          capability.sessionHash !== p.hash ||
          capability.agentId !== session.agentId ||
          capability.jkt !== session.jkt
        )
          return { revoked: false };
        this.remove(key);
        return { revoked: true };
      }
      case "execute_proxy_capability": {
        const capabilityHash = String(c.capabilityHash);
        const key = "proxy-capability:" + capabilityHash;
        const capability = this.get<ProxyCapabilityRecord>(key);
        if (!capability || capability.expiresAt <= now())
          throw new HttpError(401, "invalid_proxy_capability");
        if (capability.requestDigest !== String(c.requestDigest))
          throw new HttpError(403, "proxy_capability_request_mismatch");
        const session = this.get<Session>("session:" + capability.sessionHash);
        if (
          !session ||
          session.purpose !== "agent" ||
          session.agentId !== capability.agentId ||
          session.jkt !== capability.jkt ||
          !this.validSessionChain(capability.sessionHash, session) ||
          !session.scopes.includes("secrets:proxy")
        )
          throw new HttpError(401, "invalid_token");
        const policy = (this.get<SecretPolicy[]>("policies") || []).find(
          (item) => item.alias === capability.alias,
        );
        if (
          !policy ||
          JSON.stringify(policy) !== capability.policyBinding ||
          policy.connectionId !== capability.connectionId ||
          policy.connectionRevision !== capability.connectionRevision
        )
          throw new HttpError(403, "grant_policy_changed");
        if (
          !validateRequestPolicy(policy, capability.url, capability.method)
            .isValid
        )
          throw new HttpError(403, "policy_denied");
        const connection = policy.connectionId
          ? (this.get<any[]>("vault:connections") || []).find(
              (item) => item.id === policy.connectionId,
            )
          : null;
        if (policy.connectionId && !connection)
          throw new HttpError(503, "vault_connection_unavailable");
        if (connection && connection.revision !== policy.connectionRevision)
          throw new HttpError(503, "vault_connection_changed");
        const usageKey = "usage:" + new Date().toISOString().slice(0, 7);
        const used = this.get<number>(usageKey) || 0;
        if (used >= this.limit()) throw new HttpError(429, "quota_exceeded");
        this.put(usageKey, used + 1, now() + 70 * 86400);
        // Consume before upstream dispatch. A network error must not make the same capability
        // eligible for a second, ambiguous write attempt.
        this.remove(key);
        return {
          policy,
          vault: connection?.envelope || this.get("vault"),
          connection,
          principal: { ...session, hash: capability.sessionHash } as Principal,
        };
      }
      case "rate": {
        const key = "rate:" + String(c.key) + ":" + Math.floor(now() / 60);
        const count = this.get<number>(key) || 0;
        if (count >= Number(c.limit || 20))
          throw new HttpError(429, "rate_limited");
        this.put(key, count + 1, now() + 120);
        return true;
      }
      default:
        // Unreachable for an operation the gate admitted: `c.op` is narrowed to
        // `AuthorityOperation` above and every member has a case. It stays as a fail-closed
        // backstop so a listed operation that loses its case is refused rather than handled.
        throw new HttpError(400, "invalid_authority_command");
    }
  }
  private limit() {
    // Deployment configuration is server-owned; request/client fields never reach this limit.
    const value = Number(this.env.MONTHLY_ALLOWANCE || 10000);
    return Number.isSafeInteger(value) && value > 0 ? value : 10000;
  }
  private bindPolicies(aliases: string[]): Record<string, string> {
    const policies = this.get<SecretPolicy[]>("policies") || [];
    const bindings: Record<string, string> = {};
    for (const alias of aliases) {
      const policy = policies.find((item) => item.alias === alias);
      if (policy) bindings[alias] = JSON.stringify(policy);
    }
    return bindings;
  }
  private connectionBindings(
    aliases: string[],
  ): Record<string, VaultConnection> {
    const connections = this.get<VaultConnection[]>("vault:connections") || [];
    const policies = this.get<SecretPolicy[]>("policies") || [];
    const ids = new Set(
      policies
        .filter(
          (policy) => aliases.includes(policy.alias) && policy.connectionId,
        )
        .map((policy) => policy.connectionId!),
    );
    return Object.fromEntries(
      connections
        .filter((connection) => ids.has(connection.id))
        .map(({ id, alias, provider, revision, createdAt, updatedAt }) => [
          id,
          { id, alias, provider, revision, createdAt, updatedAt },
        ]),
    );
  }
  private selectBindings<T>(
    bindings: Record<string, T> | undefined,
    keys: string[],
  ) {
    const selected: Record<string, T> = {};
    for (const key of keys) {
      if (bindings && Object.hasOwn(bindings, key))
        selected[key] = bindings[key];
    }
    return selected;
  }
  private sameBindings(
    left: Record<string, unknown>,
    right: Record<string, unknown>,
  ) {
    const canonical = (value: Record<string, unknown>) =>
      JSON.stringify(
        Object.entries(value).sort(([a], [b]) => a.localeCompare(b)),
      );
    return canonical(left) === canonical(right);
  }
  /**
   * Create or reuse the durable deletion attempt for this DO. The generation increases
   * monotonically per account so a stale attempt's abort can never clear newer recovery state.
   */
  private prepareDeletionAttempt(
    tenantId: string | null,
  ): { accountId: string; generation: number } | null {
    const existing = this.get<{
      accountId?: string;
      generation?: number;
      requestedAt?: number;
    }>("account:deleting");
    const accountId = existing?.accountId || tenantId || "";
    if (!accountId) return null;
    const generation = Number(existing?.generation);
    if (existing && Number.isSafeInteger(generation) && generation > 0) {
      return { accountId, generation };
    }
    const next = (this.get<number>("account:deletion_generation") || 0) + 1;
    this.put("account:deletion_generation", next);
    this.put("account:deleting", {
      accountId,
      generation: next,
      requestedAt: Number(existing?.requestedAt) || now(),
    });
    return { accountId, generation: next };
  }
  /** Committed deletion cleanup: D1 tombstones/records plus the DO tombstone and purge. */
  private async completeDeletion(accountId: string, db: RegistryDatabase) {
    await recordAccountTombstone(db, accountId, "customer_requested");
    await deleteAccountRecords(db, accountId);
    this.storage.transactionSync(() => {
      this.applyCommittedDeletion();
      this.remove("account:deleting");
    });
  }
  private async scheduleCleanup() {
    try {
      if ((await this.storage.getAlarm()) === null)
        await this.storage.setAlarm(Date.now() + 60_000);
    } catch {
      console.error("authority_cleanup_schedule_failed");
    }
  }
  async alarm() {
    const deleting = this.get<{ accountId: string; generation?: number }>(
      "account:deleting",
    );
    if (deleting?.accountId) {
      const db = this.requestDatabase();
      const accountId = deleting.accountId;
      const generation = Number(deleting.generation);
      try {
        const d1Account = await findAccountById(db, accountId);
        const isTombstoned = await isAccountTombstoned(db, accountId);
        const doStatus = this.get<string>("account:status");
        const doTombstoned = Boolean(this.get("account:tombstone"));
        const doCommitted = doTombstoned || doStatus === "deleted";
        const d1Fenced = isTombstoned || d1Account?.status === "deleted";

        if (!doCommitted && !d1Fenced) {
          // Neither the DO deletion nor the D1 fence committed. An outstanding attempt may still
          // be in flight, so make the cancellation durable BEFORE releasing recovery state:
          // after this the attempt's fence can never commit, even if it arrives after the alarm.
          // A D1 `active` snapshot alone is never treated as evidence of abandonment, and a
          // missing D1 account row is ambiguous (it may have been purged) rather than a
          // committed fence.
          const outcome =
            Number.isSafeInteger(generation) && generation > 0
              ? await cancelDeletionAttempt(db, accountId, generation)
              : "superseded";
          if (outcome === "fenced") {
            // The fence did commit concurrently; finish the committed deletion.
            await this.completeDeletion(accountId, db);
          } else if (outcome === "canceled" || outcome === "absent") {
            // Do not delete account data: this fence never committed (or no attempt state
            // exists). Only now is the intent released, and only if it still belongs to the
            // attempt that was canceled.
            this.storage.transactionSync(() => {
              const current = this.get<{ generation?: number }>(
                "account:deleting",
              );
              if (Number(current?.generation) !== generation) return;
              this.remove("account:deleting");
              this.remove("account:deletion_capability");
              this.remove("account:deletion_deadline");
            });
          } else {
            // A different generation owns the durable attempt row. Keep the intent and retry
            // rather than abandoning a possibly outstanding deletion.
            await this.storage.setAlarm(Date.now() + 5000);
          }
        } else {
          // DO committed delete_account OR D1 is fenced as 'deleted'/tombstoned: proceed with full cleanup
          await this.completeDeletion(accountId, db);
        }
      } catch (d1Err) {
        // Do not swallow reschedule failure!
        await this.storage.setAlarm(Date.now() + 5000);
        // Propagate failure so platform retry semantics can run!
        throw d1Err;
      }
    }

    this.storage.exec(
      "DELETE FROM records WHERE key IN (SELECT key FROM records WHERE expires <= ? LIMIT 500)",
      now(),
    );
    // Do not let expiration cleanup overwrite the retry alarm!
    if (!this.get("account:deleting")) {
      if (
        this.storage
          .exec<{ count: number }>(
            "SELECT COUNT(*) AS count FROM records WHERE expires IS NOT NULL",
          )
          .one().count
      ) {
        await this.storage.setAlarm(Date.now() + 60_000);
      }
    }
  }
}

export function configuredTenants(env: Env): string[] {
  try {
    const tenants: unknown = JSON.parse(env.TENANTS || '["default"]');
    if (
      !Array.isArray(tenants) ||
      tenants.length > 100 ||
      tenants.some(
        (tenant) =>
          typeof tenant !== "string" || !/^[A-Za-z0-9_-]{1,80}$/.test(tenant),
      )
    )
      throw new Error();
    return [...new Set(["default", ...tenants])];
  } catch {
    throw new HttpError(503, "invalid_tenant_configuration");
  }
}
export async function authority<T>(
  env: Env,
  tenant: string,
  command: Command,
): Promise<T> {
  const isConfigured = configuredTenants(env).includes(tenant);
  if (env.DB) {
    let tombstoned = false;
    try {
      tombstoned = await isAccountTombstoned(env.DB, tenant);
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(503, "database_unavailable");
    }
    if (
      tombstoned &&
      command.op !== "delete_account" &&
      command.op !== "confirm_deleted" &&
      command.op !== "get_account_state" &&
      command.op !== "verify_deletion_credential" &&
      command.op !== "prepare_deletion" &&
      command.op !== "abort_deletion"
    ) {
      throw new HttpError(410, "account_deleted");
    }
    if (!isConfigured) {
      if (command.op === "verify_deletion_credential") {
        // Capability verification requires real registry state. Unknown tenants are rejected
        // here, before any Durable Object is allocated, and look exactly like a wrong or expired
        // credential, so the endpoint reveals nothing about which tenants exist.
        let account = null;
        try {
          account = await findAccountById(env.DB, tenant);
        } catch (error) {
          if (error instanceof HttpError) throw error;
          throw new HttpError(503, "database_unavailable");
        }
        if (!account && !tombstoned) {
          throw new HttpError(401, "unauthorized");
        }
      } else if (
        command.op === "get_account_state" ||
        command.op === "delete_account" ||
        command.op === "prepare_deletion" ||
        command.op === "abort_deletion" ||
        command.op === "confirm_deleted"
      ) {
        // Deletion lifecycle operations pass through to Durable Object for status and reconciliation
      } else {
        let account = null;
        try {
          account = await findAccountById(env.DB, tenant);
        } catch (error) {
          if (error instanceof HttpError) throw error;
          throw new HttpError(503, "database_unavailable");
        }
        if (!account) {
          if (!tombstoned) {
            throw new HttpError(401, "unknown_tenant");
          }
        } else {
          // Fail closed on a status this gate does not explicitly recognise, before any
          // status-specific branch can be read as "everything else is usable". Every value the
          // D1 guard admits is handled below; anything else can only come from a database that
          // predates (or bypassed) that guard, and an unknown lifecycle state must never be
          // treated as an authorized account. 403 rather than 401/410/503: the caller is
          // authenticated but not authorized, the account is not necessarily deleted, and the
          // condition is not a transient server fault that a retry could fix. The distinct code
          // keeps it distinguishable from a deliberate suspension (`account_disabled`) or a
          // committed deletion (`account_deleted`).
          if (!ACCOUNT_STATUSES.includes(account.status)) {
            throw new HttpError(403, "account_status_unrecognized");
          }
          if (account.status === "deleted") {
            throw new HttpError(410, "account_deleted");
          }
          if (
            account.status === "suspended" &&
            command.op !== "suspend_account"
          ) {
            throw new HttpError(403, "account_disabled");
          }
          if (
            account.status === "provisioning" &&
            command.op !== "activate_account" &&
            command.op !== "get_account_state" &&
            command.op !== "suspend_account"
          ) {
            throw new HttpError(403, "account_not_activated");
          }
        }
      }
    }
  } else if (!isConfigured) {
    throw new HttpError(401, "unknown_tenant");
  }
  if (!env.SECURITY) throw new HttpError(503, "security_authority_unavailable");
  try {
    const response = (await env.SECURITY.getByName(tenant).dispatch({
      ...command,
      tenant,
    })) as { ok: boolean; value?: T; status?: number; code?: string };
    if (!response.ok)
      throw new HttpError(
        response.status || 503,
        response.code || "authority_error",
      );
    return response.value as T;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "security_authority_unavailable");
  }
}
