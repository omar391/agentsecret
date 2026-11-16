/**
 * Platform-neutral application core.
 *
 * This module owns the AgentSecret HTTP/MCP surface as a Fetch-compatible
 * request handler plus an explicit adapter set. It deliberately contains no
 * Cloudflare runtime import: nothing here reads a Durable Object binding, a
 * D1 binding, an assets binding, an execution context, or a Workers global.
 *
 * A host supplies the adapters. The Cloudflare Worker builds them from its
 * bindings; a plain Node server builds its own SQLite, in-process authority,
 * file-backed asset store and no-op background adapter from the same set. The
 * product rules — routing, session handling, DPoP checks, account isolation,
 * revocation, reference-only results and usage accounting — are all decided
 * here rather than in either host, so the two deployments cannot drift.
 */
import type { Env, Principal, SecretPolicy } from "../types";
import { authority } from "../state/authority-kernel";
export { authority };
import { authenticate, control, sameOrigin } from "../security/auth";
import {
  authorize,
  token,
  deviceCode,
  approveDevice,
  deviceReview,
} from "../security/oauth";
import { federate } from "../security/oidc";
import { verifyProof } from "../../protocol/dpop";
import {
  executorIdForJwk,
  executorThumbprint,
  validateExecutorJwk,
} from "../../protocol/executor-id";
import {
  browserGrantTenant,
  parseBrowserGrantAction,
  parseBrowserGrantIssue,
  parseBrowserGrantRevocation,
} from "../security/browser-grant";
import {
  body,
  equal,
  hash,
  html,
  HttpError,
  json,
  now,
  isWellFormedUnicode,
  readText,
  random,
  referenceTenant,
} from "../security/primitives";
import {
  clearSessionCookie,
  refreshSession,
  requireCustomerSession,
  sessionCookie,
} from "../auth/sessions";
import {
  encryptConfig,
  decryptConfig,
  type Envelope,
} from "../vaults/encryption";
import { referenceContainsValue, validateVault } from "../vaults/manager";
import { resolveBitwarden } from "../bitwarden/client";
import {
  findSecretByReference,
  findSecretByTitle,
  writeSecret,
} from "../vaults/operations";
import { parseConnectReference, resolveConnect } from "../vaults/onepassword";
import { performAgentSecretWrite } from "../vaults/agent-write";
import {
  listProviderCapabilities,
  providerCapabilities,
} from "../vaults/capabilities";
import {
  execute,
  executeCapability,
  normalize as normalizeProxyRequest,
  validatePolicy,
} from "../broker";
import { mcp } from "../mcp/protocol";
import { socialCallback, socialRoute, socialStart } from "../auth/social";
import { CLI_MJS_SHA256 } from "../generated/cli";
import {
  completeOnboarding,
  findAccountById,
  isAccountTombstoned,
  readOnboarding,
  deleteCustomerAccount,
  type CustomerAccount,
} from "../registry";
import {
  withRegistryDatabase,
  type RegistryDatabase,
} from "../registry/database";

/** The only execution-context capability the core path uses. */
export interface BackgroundContext {
  waitUntil(promise: Promise<unknown>): void;
}

/**
 * Background work a response cannot wait for. A host that cannot run
 * background work still satisfies this contract; the request path never
 * depends on the work running.
 */
export interface BackgroundWorkAdapter {
  waitUntil(promise: Promise<unknown>): void;
}

/** Static asset serving. A host without static hosting reports false. */
export interface AssetsAdapter {
  available(): boolean;
  fetch(request: Request): Promise<Response>;
}

/**
 * Durable scheduled recovery work the host can resume after restart. Without
 * one, scheduled recovery simply never runs and the host reports false.
 */
export interface AlarmsAdapter {
  available(): boolean;
  setAlarm(when: number): Promise<void>;
}

/**
 * The account-authority seam, and the one place a host decision is made:
 * Cloudflare dispatches to a per-tenant Durable Object, a Node host runs the
 * same authority class in this process. The command set is closed and shared.
 */
export interface AccountAuthorityAdapter {
  /** True when the host can dispatch authority commands at all. */
  available(): boolean;
  dispatch(tenant: string, command: unknown): Promise<unknown>;
}

/**
 * The complete host adapter set. Every field is required so a host cannot
 * silently under-provision: a missing capability is an explicit error from
 * this module rather than an implicit fallback inside a route.
 */
export interface HostAdapters {
  assets: AssetsAdapter;
  background: BackgroundWorkAdapter;
  alarms: AlarmsAdapter;
  authority: AccountAuthorityAdapter;
}

/** One request through the application core, with its host adapters. */
export interface ApplicationRequest {
  request: Request;
  env: Env;
  adapters: HostAdapters;
}

function capabilitiesForVaultProvider(provider: unknown) {
  if (provider === "bitwarden")
    return providerCapabilities("bitwarden-secrets-manager");
  if (provider === "onepassword-connect")
    return providerCapabilities("onepassword-connect");
  if (
    provider === "bitwarden-password-manager" ||
    provider === "onepassword-service-account" ||
    provider === "lastpass"
  )
    return providerCapabilities(provider);
  throw new HttpError(500, "vault_provider_unavailable");
}

function requireDb(env: Env): RegistryDatabase {
  if (!env.DB) throw new HttpError(503, "database_unavailable");
  return env.DB;
}

/** The customer identity behind a request, resolved from the session and the registry. */
type CustomerContext = { principal: Principal; account: CustomerAccount };

/**
 * The guard every customer-facing route uses. It resolves the caller from the session cookie (or a
 * customer-issued bearer token), and requires a *customer* control session for a real registry
 * account.
 */
async function customer(request: Request, env: Env): Promise<CustomerContext> {
  const principal = await control(request, env);
  requireCustomerSession(principal);
  const account = await findAccountById(requireDb(env), principal.tenant);
  if (!account) throw new HttpError(401, "customer_session_required");
  return { principal, account };
}

/**
 * Wrap a customer route so the defined refresh point applies to it uniformly: after the handler
 * succeeds, a due session rotation is delivered as a replacement cookie. Rotation is performed by
 * the authority and never extends the absolute lifetime, so this cannot keep a session alive.
 */
async function customerRoute(
  request: Request,
  env: Env,
  handler: (context: CustomerContext) => Promise<Response>,
): Promise<Response> {
  const context = await customer(request, env);
  const crossSite = request.headers.get("Sec-Fetch-Site") === "cross-site";
  const response = await handler(context);
  const isLogout = new URL(request.url).pathname === "/api/auth/logout";
  const rotated =
    crossSite || isLogout ? null : await refreshSession(env, context.principal);
  if (rotated)
    response.headers.append(
      "Set-Cookie",
      sessionCookie(rotated, context.principal.exp - now()),
    );
  return response;
}

async function performCustomerSecretWrite(
  principal: Principal,
  input: Record<string, unknown>,
  isUpdate: boolean,
  env: Env,
  privateInput?: { requestId: string; revision: number },
) {
  if (
    Object.keys(input).sort().join(",") !==
    (isUpdate
      ? "connectionId,operationId,reference,value"
      : "connectionId,operationId,title,value")
  )
    throw new HttpError(400, "invalid_secret_save_request");
  const operationId = input.operationId;
  const connectionId = input.connectionId;
  const target = isUpdate ? input.reference : input.title;
  const value = input.value;
  if (
    typeof operationId !== "string" ||
    !/^[A-Za-z0-9_-]{20,128}$/.test(operationId) ||
    typeof connectionId !== "string" ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(connectionId) ||
    typeof target !== "string" ||
    !target.trim() ||
    !isWellFormedUnicode(target) ||
    target.length > (isUpdate ? 1024 : 128) ||
    /[\u0000-\u001f\u007f]/.test(target) ||
    typeof value !== "string" ||
    !isWellFormedUnicode(value) ||
    !value.length ||
    value.length > 8192
  )
    throw new HttpError(400, "invalid_secret_save_request");
  const payloadDigest = await hash(value);
  const connections = await authority<any[]>(env, principal.tenant, {
    op: "connections",
    principal,
  });
  const connection = connections.find((item) => item.id === connectionId);
  if (!connection) throw new HttpError(404, "vault_connection_not_found");
  if (privateInput && connection.revision !== privateInput.revision)
    throw new HttpError(409, "private_input_policy_changed");
  if (connection.provider !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");
  if (isUpdate) {
    parseConnectReference(target);
    if (referenceContainsValue(target, value))
      throw new HttpError(409, "secret_reference_not_safe");
  }
  const config = validateVault(
    await decryptConfig(connection.envelope, principal.tenant, env, {
      accountId: principal.tenant,
      connectionId: connection.id,
      revision: connection.revision,
    }),
  );
  if (config.type !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");

  const reservation = await authority<{
    status: string;
    reference?: string;
    verified?: true;
    legacyBinding?: true;
  }>(env, principal.tenant, {
    op: "reserve_secret_save",
    principal,
    operationId,
    connectionId,
    revision: connection.revision,
    title: target,
    intent: isUpdate ? "update" : "create",
    payloadDigest,
    ...(privateInput ? { privateInputRequestId: privateInput.requestId } : {}),
  });
  if (reservation.status === "saved") {
    const reference = reservation.reference || "";
    if (referenceContainsValue(reference, value))
      throw new HttpError(409, "save_outcome_unknown");
    if (reservation.legacyBinding) {
      let previousValueDigest: string | undefined;
      try {
        const previousValue = await resolveConnect(config, reference);
        if (isWellFormedUnicode(previousValue))
          previousValueDigest = await hash(previousValue);
      } catch {
        throw new HttpError(409, "save_outcome_unknown");
      }
      if (previousValueDigest !== payloadDigest)
        throw new HttpError(409, "secret_save_operation_conflict");
    }
    return {
      status: isUpdate ? "updated" : "created",
      reference,
      verified: reservation.verified === true,
      replayed: true,
    };
  }
  if (reservation.status !== "reserved")
    throw new HttpError(
      409,
      reservation.status === "unknown"
        ? "save_outcome_unknown"
        : "save_in_progress",
    );

  try {
    const receipt = await writeSecret(
      config,
      isUpdate ? "update" : "create",
      target,
      value,
    );
    const completed = await authority<{
      status: string;
      reference: string;
      verified: true;
    }>(env, principal.tenant, {
      op: "complete_secret_save",
      principal,
      operationId,
      status: "saved",
      reference: receipt.reference,
      verified: receipt.verified,
    });
    return {
      status: isUpdate ? "updated" : "created",
      reference: completed.reference,
      verified: completed.verified,
      replayed: false,
    };
  } catch {
    try {
      await authority(env, principal.tenant, {
        op: "complete_secret_save",
        principal,
        operationId,
        status: "unknown",
      });
    } catch {
      // A missing completion receipt remains in-progress and cannot dispatch a duplicate write.
    }
    throw new HttpError(503, "save_outcome_unknown");
  }
}

async function performCustomerSecretEnsure(
  principal: Principal,
  input: Record<string, unknown>,
  env: Env,
  privateInput?: { requestId: string; revision: number },
) {
  if (
    Object.keys(input).sort().join(",") !==
    "connectionId,operationId,reference,value"
  )
    throw new HttpError(400, "invalid_secret_ensure_request");
  const { operationId, connectionId, reference: target, value } = input;
  if (
    typeof operationId !== "string" ||
    !/^[A-Za-z0-9_-]{20,128}$/.test(operationId) ||
    typeof connectionId !== "string" ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(connectionId) ||
    typeof target !== "string" ||
    !target.trim() ||
    !isWellFormedUnicode(target) ||
    target.length > 1024 ||
    /[\u0000-\u001f\u007f]/.test(target) ||
    typeof value !== "string" ||
    !isWellFormedUnicode(value) ||
    !value.length ||
    value.length > 8192
  )
    throw new HttpError(400, "invalid_secret_ensure_request");

  parseConnectReference(target);
  if (referenceContainsValue(target, value))
    throw new HttpError(409, "secret_reference_not_safe");
  const payloadDigest = await hash(value);
  const connections = await authority<any[]>(env, principal.tenant, {
    op: "connections",
    principal,
  });
  const connection = connections.find((item) => item.id === connectionId);
  if (!connection) throw new HttpError(404, "vault_connection_not_found");
  if (privateInput && connection.revision !== privateInput.revision)
    throw new HttpError(409, "private_input_policy_changed");
  if (connection.provider !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");
  const config = validateVault(
    await decryptConfig(connection.envelope, principal.tenant, env, {
      accountId: principal.tenant,
      connectionId: connection.id,
      revision: connection.revision,
    }),
  );
  if (config.type !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");

  const reservation = await authority<{
    status: string;
    reference?: string;
    verified?: true;
    resultStatus?: "unchanged" | "updated";
  }>(env, principal.tenant, {
    op: "reserve_secret_save",
    principal,
    operationId,
    connectionId,
    revision: connection.revision,
    title: target,
    intent: "ensure",
    payloadDigest,
    ...(privateInput ? { privateInputRequestId: privateInput.requestId } : {}),
  });
  if (reservation.status === "saved") {
    if (
      !reservation.reference ||
      !reservation.verified ||
      !reservation.resultStatus
    )
      throw new HttpError(409, "save_outcome_unknown");
    return {
      status: reservation.resultStatus,
      reference: reservation.reference,
      verified: true,
      replayed: true,
    };
  }
  if (reservation.status !== "reserved")
    throw new HttpError(
      reservation.status === "failed" ? 502 : 409,
      reservation.status === "failed"
        ? "secret_ensure_read_failed"
        : reservation.status === "unknown"
          ? "save_outcome_unknown"
          : "save_in_progress",
    );

  let matches: boolean;
  try {
    const currentValue = await resolveConnect(config, target);
    matches = equal(currentValue, value);
  } catch {
    await authority(env, principal.tenant, {
      op: "complete_secret_save",
      principal,
      operationId,
      status: "failed",
    });
    throw new HttpError(502, "secret_ensure_read_failed");
  }

  if (matches) {
    const completed = await authority<{
      reference: string;
      verified: true;
      resultStatus: "unchanged";
    }>(env, principal.tenant, {
      op: "complete_secret_save",
      principal,
      operationId,
      status: "saved",
      resultStatus: "unchanged",
      reference: target,
      verified: true,
    });
    return {
      status: "unchanged",
      reference: completed.reference,
      verified: completed.verified,
      replayed: false,
    };
  }

  try {
    const receipt = await writeSecret(config, "update", target, value);
    const completed = await authority<{
      reference: string;
      verified: true;
      resultStatus: "updated";
    }>(env, principal.tenant, {
      op: "complete_secret_save",
      principal,
      operationId,
      status: "saved",
      resultStatus: "updated",
      reference: receipt.reference,
      verified: receipt.verified,
    });
    return {
      status: "updated",
      reference: completed.reference,
      verified: completed.verified,
      replayed: false,
    };
  } catch {
    try {
      await authority(env, principal.tenant, {
        op: "complete_secret_save",
        principal,
        operationId,
        status: "unknown",
      });
    } catch {
      // The existing reservation prevents duplicate provider dispatch on retry.
    }
    throw new HttpError(503, "save_outcome_unknown");
  }
}

async function performCustomerSecretDelete(
  principal: Principal,
  input: Record<string, unknown>,
  env: Env,
) {
  if (
    Object.keys(input).sort().join(",") !== "connectionId,operationId,reference"
  )
    throw new HttpError(400, "invalid_secret_delete_request");
  const { operationId, connectionId, reference } = input;
  if (
    typeof operationId !== "string" ||
    !/^[A-Za-z0-9_-]{20,128}$/.test(operationId) ||
    typeof connectionId !== "string" ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(connectionId) ||
    typeof reference !== "string" ||
    reference.length > 1024
  )
    throw new HttpError(400, "invalid_secret_delete_request");
  const connections = await authority<any[]>(env, principal.tenant, {
    op: "connections",
    principal,
  });
  const connection = connections.find((item) => item.id === connectionId);
  if (!connection) throw new HttpError(404, "vault_connection_not_found");
  if (connection.provider !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");
  parseConnectReference(reference);
  const config = validateVault(
    await decryptConfig(connection.envelope, principal.tenant, env, {
      accountId: principal.tenant,
      connectionId: connection.id,
      revision: connection.revision,
    }),
  );
  if (config.type !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");
  const reservation = await authority<{
    status: string;
    reference?: string;
    verified?: true;
  }>(env, principal.tenant, {
    op: "reserve_secret_save",
    principal,
    operationId,
    connectionId,
    revision: connection.revision,
    title: reference,
    intent: "delete",
  });
  if (reservation.status === "saved") {
    if (reservation.reference !== reference)
      throw new HttpError(409, "secret_save_operation_conflict");
    return {
      status: "deleted",
      reference,
      verified: reservation.verified === true,
      replayed: true,
    };
  }
  if (reservation.status !== "reserved")
    throw new HttpError(
      409,
      reservation.status === "unknown"
        ? "save_outcome_unknown"
        : "save_in_progress",
    );
  try {
    const receipt = await writeSecret(config, "delete", reference);
    const completed = await authority<{
      status: string;
      reference: string;
      verified: true;
    }>(env, principal.tenant, {
      op: "complete_secret_save",
      principal,
      operationId,
      status: "saved",
      reference: receipt.reference,
      verified: receipt.verified,
    });
    return {
      status: "deleted",
      reference: completed.reference,
      verified: completed.verified,
      replayed: false,
    };
  } catch {
    try {
      await authority(env, principal.tenant, {
        op: "complete_secret_save",
        principal,
        operationId,
        status: "unknown",
      });
    } catch {
      // The reservation remains active so retries cannot dispatch twice.
    }
    throw new HttpError(503, "save_outcome_unknown");
  }
}
async function agentSecretWrite(
  request: Request,
  env: Env,
  intent: "create" | "update" | "delete",
): Promise<Response> {
  const text = await readText(request, 16 * 1024);
  let input: Record<string, unknown>;
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new Error();
    input = value as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "invalid_secret_save_request");
  }
  const expectedKeys =
    intent === "create"
      ? "alias,operationId,title,value"
      : intent === "delete"
        ? "alias,operationId,reference"
        : "alias,operationId,reference,value";
  if (Object.keys(input).sort().join(",") !== expectedKeys)
    throw new HttpError(400, "invalid_secret_save_request");
  const { principal } = await authenticate(
    request,
    env,
    true,
    await hash(text),
  );
  return json(await performAgentSecretWrite(principal, input, intent, env));
}

async function localCompanionSecret(
  request: Request,
  env: Env,
  action: "claim" | "reserve" | "complete",
): Promise<Response> {
  const text = await readText(request, 16 * 1024);
  let input: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
      throw new Error();
    input = parsed as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "invalid_secret_save_request");
  }
  const requestHash = await hash(text);
  const { principal } = await authenticate(request, env, true, requestHash);
  const executorProof = await verifyProof(
    request,
    undefined,
    requestHash,
    "X-AgentSecret-Executor-Proof",
  );
  if (
    typeof input.executorId !== "string" ||
    !/^exe_[A-Za-z0-9_-]{43}$/u.test(input.executorId) ||
    typeof input.requestId !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(input.requestId)
  )
    throw new HttpError(400, "invalid_secret_save_request");

  if (action === "claim") {
    if (Object.keys(input).sort().join(",") !== "executorId,requestId")
      throw new HttpError(400, "invalid_secret_save_request");
    const claimed = await authority<Record<string, unknown>>(
      env,
      principal.tenant,
      {
        op: "claim_private_input",
        principal,
        requestId: input.requestId,
        executorId: input.executorId,
        executorProof,
      },
    );
    return json({
      requestId: claimed.requestId,
      operationId: claimed.operationId,
      alias: claimed.alias,
      connectionId: claimed.connectionId,
      revision: claimed.revision,
      intent: claimed.intent,
      target: claimed.target,
      status: claimed.status,
      ...(claimed.claimed === true ? { claimed: true } : {}),
      ...(claimed.reference ? { reference: claimed.reference } : {}),
      ...(claimed.verified ? { verified: claimed.verified } : {}),
      ...(claimed.resultStatus ? { resultStatus: claimed.resultStatus } : {}),
    });
  }

  if (action === "reserve") {
    if (
      Object.keys(input).sort().join(",") !==
      "alias,connectionId,executorId,intent,operationId,payloadDigest,privateInputRequestId,requestId,revision,target"
    )
      throw new HttpError(400, "invalid_secret_save_request");
    const reservation = await authority<Record<string, unknown>>(
      env,
      principal.tenant,
      {
        op: "reserve_secret_save",
        principal,
        alias: input.alias,
        operationId: input.operationId,
        connectionId: input.connectionId,
        revision: input.revision,
        title: input.target,
        intent: input.intent,
        payloadDigest: input.payloadDigest,
        privateInputRequestId: input.privateInputRequestId,
        executorId: input.executorId,
        executorProof,
      },
    );
    return json(reservation);
  }

  if (
    Object.keys(input).some(
      (key) =>
        ![
          "executorId",
          "operationId",
          "reference",
          "requestId",
          "resultStatus",
          "status",
          "verified",
        ].includes(key),
    ) ||
    typeof input.operationId !== "string" ||
    !/^[A-Za-z0-9_-]{20,128}$/.test(input.operationId) ||
    !["saved", "unknown", "rejected"].includes(String(input.status))
  )
    throw new HttpError(400, "invalid_secret_save_request");
  const completed = await authority<Record<string, unknown>>(
    env,
    principal.tenant,
    {
      op: "complete_private_input",
      principal,
      requestId: input.requestId,
      operationId: input.operationId,
      executorId: input.executorId,
      executorProof,
      status: input.status,
      ...(input.reference === undefined ? {} : { reference: input.reference }),
      ...(input.verified === undefined ? {} : { verified: input.verified }),
      ...(input.resultStatus === undefined
        ? {}
        : { resultStatus: input.resultStatus }),
    },
  );
  return json(completed);
}

async function localCompanionDelete(
  request: Request,
  env: Env,
  action: "reserve" | "complete",
): Promise<Response> {
  const text = await readText(request, 16 * 1024);
  let input: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(text);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
      throw new Error();
    input = parsed as Record<string, unknown>;
  } catch {
    throw new HttpError(400, "invalid_secret_save_request");
  }
  const requestHash = await hash(text);
  const { principal } = await authenticate(request, env, true, requestHash);
  const executorProof = await verifyProof(
    request,
    undefined,
    requestHash,
    "X-AgentSecret-Executor-Proof",
  );
  if (
    typeof input.executorId !== "string" ||
    !/^exe_[A-Za-z0-9_-]{43}$/u.test(input.executorId) ||
    typeof input.operationId !== "string" ||
    !/^[A-Za-z0-9_-]{20,128}$/.test(input.operationId) ||
    typeof input.reference !== "string"
  )
    throw new HttpError(400, "invalid_secret_save_request");
  if (action === "reserve") {
    if (
      typeof input.alias !== "string" ||
      !/^[A-Z][A-Z0-9_]{0,63}$/.test(input.alias)
    )
      throw new HttpError(400, "invalid_secret_save_request");
    if (
      Object.keys(input).sort().join(",") !==
      "alias,connectionId,executorId,operationId,reference,revision"
    )
      throw new HttpError(400, "invalid_secret_save_request");
    const authorized = await authority<any>(env, principal.tenant, {
      op: "authorize_secret_write",
      principal,
      alias: input.alias,
      intent: "delete",
    });
    if (authorized.connection.provider !== "onepassword-service-account")
      throw new HttpError(409, "provider_write_unsupported");
    const reservation = await authority<Record<string, unknown>>(
      env,
      principal.tenant,
      {
        op: "reserve_secret_save",
        principal,
        alias: input.alias,
        operationId: input.operationId,
        connectionId: input.connectionId,
        revision: input.revision,
        title: input.reference,
        intent: "delete",
        executorId: input.executorId,
        executorProof,
      },
    );
    return json(reservation);
  }
  if (
    Object.keys(input).sort().join(",") !==
      "executorId,operationId,reference,status" ||
    !["saved", "unknown"].includes(String(input.status))
  )
    throw new HttpError(400, "invalid_secret_save_request");
  const completed = await authority<Record<string, unknown>>(
    env,
    principal.tenant,
    {
      op: "complete_secret_save",
      principal,
      operationId: input.operationId,
      executorId: input.executorId,
      executorProof,
      status: input.status,
      ...(input.status === "saved"
        ? { reference: input.reference, verified: true }
        : {}),
    },
  );
  return json(completed);
}

function metadata(origin: string) {
  return {
    issuer: origin,
    authorization_endpoint: origin + "/oauth/authorize",
    token_endpoint: origin + "/oauth/token",
    device_authorization_endpoint: origin + "/oauth/device/code",
    revocation_endpoint: origin + "/oauth/revoke",
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    dpop_signing_alg_values_supported: ["ES256"],
    scopes_supported: ["secrets:proxy", "secrets:read", "secrets:write"],
  };
}

async function routes(
  request: Request,
  env: Env,
  adapters: HostAdapters,
): Promise<Response> {
  const ctx: BackgroundContext = {
    waitUntil: (promise) => adapters.background.waitUntil(promise),
  };
  const url = new URL(request.url);
  const path = url.pathname;
  const origin = env.PUBLIC_ORIGIN || url.origin;
  sameOrigin(request);
  if (request.method === "OPTIONS")
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": url.origin,
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers":
          "Authorization, DPoP, Content-Type, MCP-Protocol-Version",
        Vary: "Origin",
      },
    });
  if (path === "/health" || path === "/api/info")
    return json({
      service: "agentsecret",
      version: "3.0.0",
      profile: "strict-broker",
      configured: adapters.authority.available(),
      providers: ["bitwarden", "companion"],
      providerModes: listProviderCapabilities(),
      rawExport: false,
      mcp: "/mcp",
      billing: false,
    });
  if (path === "/.well-known/oauth-authorization-server")
    return json(metadata(origin));
  if (path === "/.well-known/oauth-protected-resource")
    return json({
      resource: origin,
      authorization_servers: [origin],
      scopes_supported: ["secrets:proxy", "secrets:read", "secrets:write"],
      bearer_methods_supported: ["header"],
    });
  if (path === "/oauth/authorize") return authorize(request, env, url);
  if (path === "/oauth/token" && request.method === "POST")
    return token(request, env);
  if (path === "/oauth/device/code" && request.method === "POST")
    return deviceCode(request, env);
  if (path === "/oauth/token/oidc" && request.method === "POST")
    return federate(request, env);
  if (path === "/api/device/approve" && request.method === "POST")
    return customerRoute(request, env, ({ principal }) =>
      approveDevice(request, env, principal),
    );
  if (path === "/api/auth/me" && request.method === "GET") {
    try {
      return await customerRoute(
        request,
        env,
        async ({ principal, account }) => {
          const usage = await authority<{
            currentUsage: number;
            monthlyAllowance: number;
          }>(env, principal.tenant, { op: "account", principal });
          const onboarding = await readOnboarding(
            requireDb(env),
            principal.tenant,
          );
          // Every field is the customer's own: there is no operator fallback identity, no plan or
          // provider invented by this server, and no tenant list to switch through.
          return json({
            authenticated: true,
            user: {
              id: principal.tenant,
              name: onboarding.displayName || account.name,
              email: account.email || "",
              avatarUrl: account.avatarUrl,
              provider: "customer",
              plan: "self-hosted",
              quotaUsed: usage.currentUsage,
              quotaLimit: usage.monthlyAllowance,
              onboarding: {
                complete: onboarding.complete,
                displayName: onboarding.displayName,
              },
            },
          });
        },
      );
    } catch (error) {
      // An unauthenticated browser is a normal state for the dashboard to poll for.
      if (error instanceof HttpError && error.status !== 503)
        return json({ authenticated: false }, 401);
      throw error;
    }
  }
  if (path === "/api/auth/logout" && request.method === "POST") {
    return customerRoute(request, env, async ({ principal }) => {
      await authority(env, principal.tenant, { op: "logout", principal });
      const response = json({ success: true });
      response.headers.set("Set-Cookie", clearSessionCookie());
      return response;
    });
  }
  if (path === "/api/user/onboarding" && request.method === "POST") {
    return customerRoute(request, env, async ({ principal }) => {
      const input = await body(request);
      const name = typeof input.name === "string" ? input.name.trim() : "";
      // A display name is the whole onboarding requirement. No email is asked for, verified or
      // required: a provider that returned no address, or an unverified one, cannot block this.
      if (!name || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name))
        throw new HttpError(400, "invalid_profile");
      const onboarding = await completeOnboarding(
        requireDb(env),
        principal.tenant,
        name,
      );
      return json({ success: true, onboarding });
    });
  }
  if (path === "/device" && request.method === "GET") {
    if (url.searchParams.has("code")) return deviceReview(request, env);
    return html(
      `<h1>Approve a device</h1><p>Sign in to your AgentSecret account first, then open the verification link shown by a device you control.</p><a href="/?view=dashboard">Sign in</a>`,
    );
  }
  if (path === "/device" && request.method === "POST") {
    await approveDevice(request, env);
    return html(
      "<h1>Device approved</h1><p>Return to the requesting device.</p>",
    );
  }
  if (path === "/api/user/resolve-cli")
    return json(
      {
        error: "secret_export_disabled",
        message:
          "Strict mode performs authorized requests through the broker. Raw credentials cannot be exported to local commands.",
      },
      410,
    );
  if (path === "/api/auth/demo" || path === "/sse" || path === "/message")
    return json(
      { error: "legacy_endpoint_removed", mcp: origin + "/mcp" },
      410,
    );
  if (path.startsWith("/api/billing/"))
    return json({ error: "feature_not_configured" }, 501);
  if (path.startsWith("/auth/")) {
    // Customer social sign-in lives on exactly four routes, separate from this server's own
    // `/oauth/*` authorization server for agents. Any other path under `/auth/` stays unimplemented
    // rather than being routed by prefix.
    const route = socialRoute(path);
    if (!route) return json({ error: "feature_not_configured" }, 501);
    if (request.method !== "GET")
      return new Response(null, { status: 405, headers: { Allow: "GET" } });
    return route.phase === "callback"
      ? socialCallback(request, env, url, route.provider)
      : socialStart(request, env, url, route.provider);
  }
  if (path === "/cli.mjs" || path === "/run.mjs") {
    if (!adapters.assets.available())
      throw new HttpError(503, "cli_artifact_unavailable");
    const assetUrl = new URL(request.url);
    assetUrl.pathname = "/cli.mjs";
    const asset = await adapters.assets.fetch(new Request(assetUrl, request));
    if (!asset.ok) throw new HttpError(503, "cli_artifact_unavailable");
    const headers = new Headers(asset.headers);
    headers.set("Content-Type", "application/javascript");
    headers.set("Cache-Control", "no-store");
    headers.set("X-Content-Type-Options", "nosniff");
    return new Response(asset.body, { headers });
  }
  if (path === "/cli.mjs.sha256")
    return json({ sha256: CLI_MJS_SHA256, encoding: "base64url" });
  if (path === "/mcp") {
    if (request.method !== "POST")
      return new Response(null, { status: 405, headers: { Allow: "POST" } });
    const protocol = request.headers.get("MCP-Protocol-Version");
    if (protocol && !["2025-06-18", "2025-03-26"].includes(protocol))
      throw new HttpError(400, "unsupported_mcp_version");
    return mcp(request, env, ctx, await readText(request, 64 * 1024));
  }
  if (path === "/proxy" && request.method === "POST") {
    const text = await readText(request, 64 * 1024);
    let input: unknown;
    try {
      input = JSON.parse(text);
    } catch {
      throw new HttpError(400, "invalid_request");
    }
    const digest = await hash(text);
    const { principal, proof } = await authenticate(
      request,
      env,
      false,
      digest,
    );
    return json(await execute(input, principal, proof, digest, env, ctx));
  }
  if (path === "/proxy/capability" && request.method === "POST") {
    const authorization = request.headers.get("Authorization") || "";
    const capability =
      /^AgentSecret (aspc1\.[A-Za-z0-9_-]{1,80}\.[A-Za-z0-9_-]{32,128})$/.exec(
        authorization,
      )?.[1];
    if (!capability) throw new HttpError(401, "invalid_proxy_capability");
    const text = await readText(request, 64 * 1024);
    let input: unknown;
    try {
      input = JSON.parse(text);
    } catch {
      throw new HttpError(400, "invalid_request");
    }
    return json(await executeCapability(input, capability, env, ctx));
  }
  if (
    path === "/api/agent/proxy-capabilities/revoke" &&
    request.method === "POST"
  ) {
    const text = await readText(request, 4096);
    let input: unknown;
    try {
      input = JSON.parse(text);
    } catch {
      throw new HttpError(400, "invalid_request");
    }
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).length !== 1 ||
      typeof (input as { capability?: unknown }).capability !== "string"
    )
      throw new HttpError(400, "invalid_proxy_capability");
    const capability = (input as { capability: string }).capability;
    const match = /^aspc1\.([A-Za-z0-9_-]{1,80})\.[A-Za-z0-9_-]{32,128}$/.exec(
      capability,
    );
    if (!match) throw new HttpError(400, "invalid_proxy_capability");
    const digest = await hash(text);
    const { principal, proof } = await authenticate(
      request,
      env,
      false,
      digest,
    );
    if (principal.purpose !== "agent" || match[1] !== principal.tenant)
      throw new HttpError(403, "proxy_capability_forbidden");
    return json(
      await authority<{ revoked: boolean }>(env, principal.tenant, {
        op: "revoke_proxy_capability",
        principal,
        proof,
        requestHash: digest,
        capabilityHash: await hash(capability),
      }),
    );
  }
  if (path === "/api/agent/proxy-capabilities" && request.method === "POST") {
    const text = await readText(request, 64 * 1024);
    let input: unknown;
    try {
      input = JSON.parse(text);
    } catch {
      throw new HttpError(400, "invalid_request");
    }
    const digest = await hash(text);
    const { principal, proof } = await authenticate(
      request,
      env,
      false,
      digest,
    );
    if (principal.purpose !== "agent")
      throw new HttpError(403, "agent_session_required");
    const params = normalizeProxyRequest(input);
    const capability = `aspc1.${principal.tenant}.${random(32)}`;
    const created = await authority<{ expiresAt: number }>(
      env,
      principal.tenant,
      {
        op: "create_proxy_capability",
        principal,
        proof,
        requestHash: digest,
        capabilityHash: await hash(capability),
        requestDigest: await hash(JSON.stringify(params)),
        alias: params.secret_alias,
        url: params.url,
        method: params.method,
      },
    );
    return json({ capability, expiresAt: created.expiresAt });
  }
  if (path === "/api/agent/secrets/save" && request.method === "POST")
    return agentSecretWrite(request, env, "create");
  if (path === "/api/agent/secrets/provider" && request.method === "GET") {
    const url = new URL(request.url);
    const alias = url.searchParams.get("alias") || "";
    const intent = url.searchParams.get("intent") || "";
    if (
      [...url.searchParams.keys()].sort().join(",") !== "alias,intent" ||
      !/^[A-Z][A-Z0-9_]{0,63}$/.test(alias) ||
      !["create", "update", "delete"].includes(intent)
    )
      throw new HttpError(400, "invalid_secret_save_request");
    const { principal } = await authenticate(request, env, true);
    const authorized = await authority<{
      connection: { id: string; revision: number; provider: string };
    }>(env, principal.tenant, {
      op: "authorize_secret_write",
      principal,
      alias,
      intent,
    });
    return json({
      provider: authorized.connection.provider,
      connectionId: authorized.connection.id,
      revision: authorized.connection.revision,
    });
  }
  if (
    [
      "/api/agent/secrets/local-companion/claim",
      "/api/agent/secrets/local-companion/reserve",
      "/api/agent/secrets/local-companion/complete",
    ].includes(path) &&
    request.method === "POST"
  )
    return localCompanionSecret(
      request,
      env,
      path.endsWith("/claim")
        ? "claim"
        : path.endsWith("/reserve")
          ? "reserve"
          : "complete",
    );
  if (
    [
      "/api/agent/secrets/local-companion/delete-reserve",
      "/api/agent/secrets/local-companion/delete-complete",
    ].includes(path) &&
    request.method === "POST"
  )
    return localCompanionDelete(
      request,
      env,
      path.endsWith("/delete-reserve") ? "reserve" : "complete",
    );
  if (path === "/api/agent/status" && request.method === "GET") {
    const { principal } = await authenticate(request, env, true);
    if (principal.purpose !== "agent")
      throw new HttpError(403, "agent_session_required");
    return json({ status: "authenticated", expiresAt: principal.exp });
  }
  if (path === "/api/agent/logout" && request.method === "POST") {
    const { principal } = await authenticate(request, env, true);
    if (principal.purpose !== "agent")
      throw new HttpError(403, "agent_session_required");
    await authority(env, principal.tenant, {
      op: "revoke_agent_session",
      principal,
    });
    return json({ success: true });
  }
  if (path === "/api/agent/secrets/update" && request.method === "POST")
    return agentSecretWrite(request, env, "update");
  if (path === "/api/agent/secrets/delete" && request.method === "POST")
    return agentSecretWrite(request, env, "delete");
  if (path === "/api/user/policies") {
    if (request.method === "GET") {
      return customerRoute(request, env, async ({ principal }) =>
        json({
          policies: await authority(env, principal.tenant, {
            op: "policies",
            principal,
          }),
        }),
      );
    }
    if (request.method === "POST") {
      return customerRoute(request, env, async ({ principal }) => {
        const policy = validatePolicy(await body(request));
        await authority(env, principal.tenant, {
          op: "save_policy",
          principal,
          policy,
        });
        return json({ success: true });
      });
    }
    if (request.method === "PATCH") {
      return customerRoute(request, env, async ({ principal }) => {
        const input = (await body(request)) as Record<string, unknown>;
        if (
          !input ||
          Array.isArray(input) ||
          Object.keys(input).sort().join(",") !== "alias,findSelector" ||
          typeof input.alias !== "string" ||
          !/^[A-Z][A-Z0-9_]{0,63}$/.test(input.alias) ||
          (input.findSelector !== null &&
            (!input.findSelector ||
              typeof input.findSelector !== "object" ||
              Array.isArray(input.findSelector)))
        )
          throw new HttpError(400, "invalid_policy_find_selector");
        const policies = (await authority<SecretPolicy[]>(
          env,
          principal.tenant,
          { op: "policies", principal },
        )) as SecretPolicy[];
        const current = policies.find((policy) => policy.alias === input.alias);
        if (!current) throw new HttpError(404, "policy_not_found");
        if (!current.connectionId || !current.secretId)
          throw new HttpError(409, "explicit_secret_reference_required");
        const connections = (await authority<
          Array<{ id: string; revision: number; provider: string }>
        >(env, principal.tenant, { op: "connections", principal })) as Array<{
          id: string;
          revision: number;
          provider: string;
        }>;
        const connection = connections.find(
          (item) => item.id === current.connectionId,
        );
        if (connection?.provider !== "onepassword-connect")
          throw new HttpError(409, "provider_selector_unsupported");
        let findSelector: SecretPolicy["findSelector"];
        if (input.findSelector !== null) {
          const candidate = input.findSelector as SecretPolicy["findSelector"];
          const ref = parseConnectReference(current.secretId);
          if (
            !candidate ||
            candidate.kind !== "login_lookup" ||
            candidate.fieldId !== ref.fieldId
          )
            throw new HttpError(400, "invalid_policy_find_selector");
          findSelector = validatePolicy({
            ...current,
            findSelector: candidate,
          }).findSelector;
        }
        await authority(env, principal.tenant, {
          op: "update_policy_find_selector",
          principal,
          alias: current.alias,
          expectedConnectionId: current.connectionId,
          expectedConnectionRevision: current.connectionRevision,
          expectedSecretId: current.secretId,
          findSelector,
        });
        return json({ success: true });
      });
    }
    if (request.method === "DELETE") {
      return customerRoute(request, env, async ({ principal }) => {
        const alias = url.searchParams.get("alias");
        if (!alias) throw new HttpError(400, "alias_required");
        await authority(env, principal.tenant, {
          op: "delete_policy",
          principal,
          alias,
        });
        return json({ success: true });
      });
    }
  }
  if (path === "/api/user/vaults") {
    if (request.method === "GET") {
      // Metadata only. The decrypted provider type is the one field the customer already knows;
      // the access token and every other configuration value stay sealed in the envelope and
      // never appear in a response, a log line or a URL.
      return customerRoute(request, env, async ({ principal }) => {
        const stored = await authority<Envelope | null>(env, principal.tenant, {
          op: "vault",
          principal,
        });
        if (!stored) return json({ configured: false, provider: null });
        const config = (await decryptConfig(stored, principal.tenant, env)) as {
          type?: unknown;
        };
        return json({
          configured: true,
          provider: typeof config?.type === "string" ? config.type : "unknown",
        });
      });
    }
    if (request.method === "POST") {
      return customerRoute(request, env, async ({ principal }) => {
        const input = await body(request);
        const config = validateVault(input.config);
        const envelope = await encryptConfig(config, principal.tenant, env);
        await authority(env, principal.tenant, {
          op: "save_vault",
          principal,
          envelope,
        });
        return json({ success: true, provider: config.type });
      });
    }
  }
  if (path === "/api/user/vault-connections") {
    if (request.method === "GET")
      return customerRoute(request, env, async ({ principal }) => {
        const connections = await authority<any[]>(env, principal.tenant, {
          op: "connections",
          principal,
        });
        return json({
          providerCapabilities: listProviderCapabilities(),
          connections: connections.map(
            ({ id, alias, provider, revision, createdAt, updatedAt }) => ({
              id,
              alias,
              provider,
              capabilities: capabilitiesForVaultProvider(provider),
              revision,
              createdAt,
              updatedAt,
            }),
          ),
        });
      });
    if (request.method === "POST" || request.method === "PATCH")
      return customerRoute(request, env, async ({ principal }) => {
        const input = (await body(request)) as {
          id?: string;
          alias?: string;
          config?: unknown;
        };
        if (
          typeof input.alias !== "string" ||
          !/^[A-Za-z0-9_-]{1,64}$/.test(input.alias)
        )
          throw new HttpError(400, "invalid_vault_connection_alias");
        const connections = await authority<any[]>(env, principal.tenant, {
          op: "connections",
          principal,
        });
        const old =
          request.method === "PATCH"
            ? connections.find((item) => item.id === input.id)
            : undefined;
        if (request.method === "PATCH" && !old)
          throw new HttpError(404, "vault_connection_not_found");
        const config = validateVault(input.config);
        const id = old?.id || random(24);
        const revision = (old?.revision || 0) + 1;
        const envelope = await encryptConfig(config, principal.tenant, env, {
          accountId: principal.tenant,
          connectionId: id,
          revision,
        });
        const time = now();
        const connection = {
          id,
          alias: input.alias,
          provider: config.type,
          revision,
          createdAt: old?.createdAt || time,
          updatedAt: time,
          envelope,
        };
        await authority(env, principal.tenant, {
          op: "save_connection",
          principal,
          connection,
        });
        return json({
          success: true,
          connection: {
            id,
            alias: input.alias,
            provider: config.type,
            capabilities: capabilitiesForVaultProvider(config.type),
            revision,
            createdAt: connection.createdAt,
            updatedAt: time,
          },
        });
      });
    if (request.method === "DELETE")
      return customerRoute(request, env, async ({ principal }) => {
        const id = url.searchParams.get("id");
        if (!id) throw new HttpError(400, "vault_connection_id_required");
        await authority(env, principal.tenant, {
          op: "delete_connection",
          principal,
          id,
        });
        return json({ success: true });
      });
  }
  if (path === "/api/user/secrets/find" && request.method === "POST")
    return customerRoute(request, env, async ({ principal }) => {
      const input = await body(request);
      const keys = Object.keys(input).sort().join(",");
      const byReference = keys === "connectionId,reference";
      const bySelector = keys === "connectionId,selector";
      const selectorObject =
        input.selector &&
        typeof input.selector === "object" &&
        !Array.isArray(input.selector)
          ? (input.selector as Record<string, unknown>)
          : undefined;
      if (
        (!byReference && !bySelector) ||
        typeof input.connectionId !== "string" ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(input.connectionId) ||
        (byReference &&
          (typeof input.reference !== "string" ||
            !input.reference.trim() ||
            input.reference.length > 1024 ||
            /[\u0000-\u001f\u007f]/.test(input.reference))) ||
        (bySelector &&
          (!selectorObject ||
            !["title", "fieldId,title"].includes(
              Object.keys(selectorObject).sort().join(","),
            ) ||
            typeof selectorObject.title !== "string" ||
            !selectorObject.title.trim() ||
            selectorObject.title.length > 128 ||
            /[\u0000-\u001f\u007f]/.test(selectorObject.title) ||
            (selectorObject.fieldId !== undefined &&
              (typeof selectorObject.fieldId !== "string" ||
                !selectorObject.fieldId ||
                selectorObject.fieldId.length > 256 ||
                /[\u0000-\u001f\u007f]/.test(selectorObject.fieldId)))))
      )
        throw new HttpError(400, "invalid_secret_find_request");

      const connections = await authority<any[]>(env, principal.tenant, {
        op: "connections",
        principal,
      });
      const connection = connections.find(
        (item) => item.id === input.connectionId,
      );
      if (!connection) throw new HttpError(404, "vault_connection_not_found");
      const config = validateVault(
        await decryptConfig(connection.envelope, principal.tenant, env, {
          accountId: principal.tenant,
          connectionId: connection.id,
          revision: connection.revision,
        }),
      );
      if (config.type !== connection.provider)
        throw new HttpError(409, "vault_connection_changed");
      if (bySelector)
        await authority(env, principal.tenant, {
          op: "rate",
          key: "customer-secret-find-selector:" + principal.tenant,
          limit: 20,
        });
      const result = byReference
        ? await findSecretByReference(config, input.reference as string)
        : await findSecretByTitle(
            config,
            selectorObject!.title as string,
            selectorObject!.fieldId as string | undefined,
          );
      return json(result);
    });
  if (path === "/api/user/secrets/ensure" && request.method === "POST")
    return customerRoute(request, env, async ({ principal }) => {
      const input = await body(request);
      await authority(env, principal.tenant, {
        op: "rate",
        key: "customer-secret-ensure:" + principal.tenant,
        limit: 5,
      });
      return json(await performCustomerSecretEnsure(principal, input, env));
    });
  if (path === "/api/user/secrets/compare" && request.method === "POST")
    return customerRoute(request, env, async ({ principal }) => {
      const input = await body(request);
      if (
        Object.keys(input).sort().join(",") !==
          "connectionId,reference,value" ||
        typeof input.connectionId !== "string" ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(input.connectionId) ||
        typeof input.reference !== "string" ||
        !input.reference.trim() ||
        input.reference.length > 1024 ||
        /[\u0000-\u001f\u007f]/.test(input.reference) ||
        typeof input.value !== "string" ||
        !input.value.length ||
        input.value.length > 8192 ||
        !isWellFormedUnicode(input.value)
      )
        throw new HttpError(400, "invalid_secret_compare_request");

      await authority(env, principal.tenant, {
        op: "rate",
        key: "customer-secret-compare:" + principal.tenant,
        limit: 5,
      });
      const connections = await authority<any[]>(env, principal.tenant, {
        op: "connections",
        principal,
      });
      const connection = connections.find(
        (item) => item.id === input.connectionId,
      );
      if (!connection) throw new HttpError(404, "vault_connection_not_found");
      if (
        connection.provider !== "bitwarden" &&
        connection.provider !== "onepassword-connect"
      )
        throw new HttpError(409, "provider_read_unsupported");
      const config = validateVault(
        await decryptConfig(connection.envelope, principal.tenant, env, {
          accountId: principal.tenant,
          connectionId: connection.id,
          revision: connection.revision,
        }),
      );
      if (config.type !== connection.provider)
        throw new HttpError(409, "vault_connection_changed");
      const storedValue =
        config.type === "bitwarden"
          ? await resolveBitwarden(config, input.reference)
          : config.type === "onepassword-connect"
            ? await resolveConnect(config, input.reference)
            : (() => {
                throw new HttpError(409, "provider_read_unsupported");
              })();
      // This customer-control operation intentionally returns only a comparison result. It is not
      // exposed through MCP or agent routes, so callers cannot turn it into a password-guess oracle.
      return json({ matches: equal(storedValue, input.value) });
    });
  if (
    ["/api/user/secrets/save", "/api/user/secrets/update"].includes(path) &&
    request.method === "POST"
  )
    return customerRoute(request, env, async ({ principal }) => {
      const isUpdate = path === "/api/user/secrets/update";
      const input = await body(request);
      return json(
        await performCustomerSecretWrite(principal, input, isUpdate, env),
      );
    });
  if (path === "/api/user/secrets/delete" && request.method === "POST")
    return customerRoute(request, env, async ({ principal }) =>
      json(
        await performCustomerSecretDelete(principal, await body(request), env),
      ),
    );
  if (path === "/api/user/secrets/private-inputs" && request.method === "GET")
    return customerRoute(request, env, async ({ principal }) => {
      const cursor =
        new URL(request.url).searchParams.get("cursor") || undefined;
      return json(
        await authority<{ requests: unknown[]; nextCursor: string | null }>(
          env,
          principal.tenant,
          {
            op: "list_private_inputs",
            principal,
            ...(cursor ? { cursor } : {}),
          },
        ),
      );
    });
  if (path === "/api/user/secrets/private-inputs" && request.method === "POST")
    return customerRoute(request, env, async ({ principal }) => {
      const input = await body(request);
      if (
        Object.keys(input).sort().join(",") !== "requestId,value" ||
        typeof input.requestId !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(input.requestId) ||
        typeof input.value !== "string" ||
        !input.value.length ||
        input.value.length > 8192 ||
        !isWellFormedUnicode(input.value)
      )
        throw new HttpError(400, "invalid_private_input_request");
      const pending = await authority<{
        requestId: string;
        operationId: string;
        connectionId: string;
        revision: number;
        intent: "create" | "update" | "ensure";
        target: string;
        status: string;
        claimed?: boolean;
        reference?: string;
        verified?: true;
        resultStatus?: "unchanged" | "updated";
      }>(env, principal.tenant, {
        op: "claim_private_input",
        principal,
        requestId: input.requestId,
      });
      if (pending.status === "unknown")
        throw new HttpError(409, "save_outcome_unknown");
      if (!["pending", "fulfilling", "saved"].includes(pending.status))
        throw new HttpError(409, "private_input_request_not_pending");
      if (pending.status === "fulfilling" && pending.claimed !== true)
        throw new HttpError(409, "save_in_progress");
      try {
        const receipt =
          pending.intent === "ensure"
            ? await performCustomerSecretEnsure(
                principal,
                {
                  connectionId: pending.connectionId,
                  operationId: pending.operationId,
                  reference: pending.target,
                  value: input.value,
                },
                env,
                { requestId: pending.requestId, revision: pending.revision },
              )
            : await performCustomerSecretWrite(
                principal,
                {
                  connectionId: pending.connectionId,
                  operationId: pending.operationId,
                  ...(pending.intent === "update"
                    ? { reference: pending.target }
                    : { title: pending.target }),
                  value: input.value,
                },
                pending.intent === "update",
                env,
                { requestId: pending.requestId, revision: pending.revision },
              );
        await authority(env, principal.tenant, {
          op: "complete_private_input",
          principal,
          requestId: pending.requestId,
          status: "saved",
          reference: receipt.reference,
          verified: receipt.verified,
          ...(pending.intent === "ensure" &&
          (receipt.status === "unchanged" || receipt.status === "updated")
            ? { resultStatus: receipt.status }
            : {}),
        });
        return json(receipt);
      } catch (error) {
        const status =
          error instanceof HttpError &&
          ((error.status >= 500 &&
            error.code !== "secret_ensure_read_failed") ||
            error.code === "save_outcome_unknown" ||
            error.code === "save_in_progress")
            ? "unknown"
            : "rejected";
        try {
          await authority(env, principal.tenant, {
            op: "complete_private_input",
            principal,
            requestId: pending.requestId,
            status,
          });
        } catch {
          // The value is discarded regardless; an incomplete ticket cannot dispatch on its own.
        }
        throw error;
      }
    });
  if (path === "/api/user/vault-connections/rekey" && request.method === "POST")
    return customerRoute(request, env, async ({ principal }) => {
      const connections = await authority<any[]>(env, principal.tenant, {
        op: "connections",
        principal,
      });
      const replacements = [];
      for (const current of connections) {
        const config = await decryptConfig(
          current.envelope,
          principal.tenant,
          env,
          {
            accountId: principal.tenant,
            connectionId: current.id,
            revision: current.revision,
          },
        );
        const revision = current.revision + 1;
        const envelope = await encryptConfig(config, principal.tenant, env, {
          accountId: principal.tenant,
          connectionId: current.id,
          revision,
        });
        replacements.push({
          id: current.id,
          expectedRevision: current.revision,
          connection: { ...current, revision, envelope, updatedAt: now() },
        });
      }
      await authority(env, principal.tenant, {
        op: "rekey_connections",
        principal,
        connections: replacements,
      });
      return json({ success: true, rekeyed: replacements.length });
    });
  if (path === "/api/user/vaults/rekey" && request.method === "POST") {
    return customerRoute(request, env, async ({ principal }) => {
      const stored = await authority<Envelope>(env, principal.tenant, {
        op: "vault",
        principal,
      });
      const envelope = await encryptConfig(
        await decryptConfig(stored, principal.tenant, env),
        principal.tenant,
        env,
      );
      await authority(env, principal.tenant, {
        op: "save_vault",
        principal,
        envelope,
      });
      return json({ success: true });
    });
  }
  if (path === "/api/executor/enroll") {
    if (request.method !== "POST")
      throw new HttpError(405, "method_not_allowed");
    return customerRoute(request, env, async ({ principal }) => {
      const text = await request.text();
      if (text.length > 8192) throw new HttpError(413, "request_too_large");
      let parsed: {
        executorId?: unknown;
        publicJwk?: unknown;
        createdAt?: unknown;
      };
      try {
        parsed = JSON.parse(text) as typeof parsed;
      } catch {
        throw new HttpError(400, "invalid_executor_identity");
      }
      if (
        !parsed ||
        Array.isArray(parsed) ||
        Object.keys(parsed).some(
          (key) => !["createdAt", "executorId", "publicJwk"].includes(key),
        )
      )
        throw new HttpError(400, "invalid_executor_identity");
      let jwk: JsonWebKey;
      try {
        jwk = validateExecutorJwk(parsed?.publicJwk);
      } catch {
        throw new HttpError(400, "invalid_executor_identity");
      }
      const executorId = await executorIdForJwk(jwk);
      if (parsed?.executorId !== executorId)
        throw new HttpError(400, "invalid_executor_identity");
      const proof = await verifyProof(request);
      const thumbprint = await executorThumbprint(jwk);
      if (proof.jkt !== thumbprint)
        throw new HttpError(401, "invalid_dpop_proof");
      const result = await authority(env, principal.tenant, {
        op: "enroll_executor",
        principal,
        executor: {
          executorId,
          thumbprint,
          publicJwk: jwk,
          createdAt: parsed?.createdAt,
        },
      });
      return json(result);
    });
  }
  if (path === "/api/executor/approve") {
    if (request.method !== "POST")
      throw new HttpError(405, "method_not_allowed");
    return customerRoute(request, env, async ({ principal }) => {
      const text = await readText(request, 8192);
      let parsed: {
        executorId?: unknown;
        publicJwk?: unknown;
        createdAt?: unknown;
      };
      try {
        parsed = JSON.parse(text) as typeof parsed;
      } catch {
        throw new HttpError(400, "invalid_executor_identity");
      }
      if (
        !parsed ||
        Array.isArray(parsed) ||
        Object.keys(parsed).some(
          (key) => !["createdAt", "executorId", "publicJwk"].includes(key),
        )
      )
        throw new HttpError(400, "invalid_executor_identity");
      let jwk: JsonWebKey;
      try {
        jwk = validateExecutorJwk(parsed?.publicJwk);
      } catch {
        throw new HttpError(400, "invalid_executor_identity");
      }
      const executorId = await executorIdForJwk(jwk);
      if (parsed?.executorId !== executorId)
        throw new HttpError(400, "invalid_executor_identity");
      return json(
        await authority(env, principal.tenant, {
          op: "enroll_executor",
          principal,
          executor: {
            executorId,
            thumbprint: await executorThumbprint(jwk),
            publicJwk: jwk,
            createdAt: parsed?.createdAt,
          },
        }),
      );
    });
  }
  if (path === "/api/executor/identities") {
    if (request.method !== "GET")
      throw new HttpError(405, "method_not_allowed");
    return customerRoute(request, env, async ({ principal }) =>
      json({
        executors: await authority(env, principal.tenant, {
          op: "list_executors",
          principal,
        }),
      }),
    );
  }
  if (path === "/api/executor/grants") {
    if (request.method === "GET")
      return customerRoute(request, env, async ({ principal }) =>
        json({
          grants: await authority(env, principal.tenant, {
            op: "list_browser_grants",
            principal,
          }),
        }),
      );
    if (request.method !== "POST")
      throw new HttpError(405, "method_not_allowed");
    return customerRoute(request, env, async ({ principal }) => {
      const grant = parseBrowserGrantIssue(await body(request), now());
      const issued = await authority<Record<string, unknown>>(
        env,
        principal.tenant,
        {
          op: "issue_browser_grant",
          principal,
          grant,
        },
      );
      return json(issued, 201);
    });
  }
  if (path === "/api/executor/grants/redeem") {
    if (request.method !== "POST")
      throw new HttpError(405, "method_not_allowed");
    const text = await readText(request, 8192);
    let input: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(text);
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object")
        throw new Error();
      input = parsed as Record<string, unknown>;
    } catch {
      throw new HttpError(400, "invalid_browser_grant");
    }
    const action = parseBrowserGrantAction(input);
    const tenant = browserGrantTenant(action.grantId);
    const proof = await verifyProof(request, undefined, await hash(text));
    const receipt = await authority(env, tenant, {
      op: "redeem_browser_grant",
      action,
      proof,
    });
    return json(receipt);
  }
  if (path === "/api/executor/grants/revoke") {
    if (request.method !== "POST")
      throw new HttpError(405, "method_not_allowed");
    return customerRoute(request, env, async ({ principal }) => {
      const grantId = parseBrowserGrantRevocation(await body(request));
      const tenant = browserGrantTenant(grantId);
      if (tenant !== principal.tenant)
        throw new HttpError(403, "browser_grant_account_mismatch");
      return json(
        await authority(env, principal.tenant, {
          op: "revoke_browser_grant",
          principal,
          grantId,
        }),
      );
    });
  }
  if (path === "/api/executor/revoke") {
    if (request.method !== "POST")
      throw new HttpError(405, "method_not_allowed");
    return customerRoute(request, env, async ({ principal }) => {
      const input = await body(request);
      if (
        Object.keys(input).join(",") !== "executorId" ||
        typeof input.executorId !== "string" ||
        !/^exe_[A-Za-z0-9_-]{43}$/u.test(input.executorId)
      )
        throw new HttpError(400, "invalid_executor_identity");
      return json(
        await authority(env, principal.tenant, {
          op: "revoke_executor",
          principal,
          executorId: input.executorId,
        }),
      );
    });
  }
  if (path === "/api/user/account") {
    if (request.method === "GET") {
      return customerRoute(request, env, async ({ principal }) =>
        json(
          await authority(env, principal.tenant, { op: "account", principal }),
        ),
      );
    }
    if (request.method === "DELETE") {
      let tenant: string;
      let deletionTokenHash: string | undefined;
      let retryTtl: number | undefined;
      // Browser (cookie) credentials are only accepted from a verifiable same-origin caller.
      // This runs before the authentication attempt, so an origin denial can never be downgraded
      // into the capability fallback. Bearer-only, non-browser clients are unaffected.
      const forwardedCookie = Boolean(
        request.headers
          .get("Cookie")
          ?.split(";")
          .some((item) => item.trim().startsWith("agentsecret_session=")),
      );
      if (forwardedCookie) sameOrigin(request, true);
      // The workload/operator bootstrap credential is refused outright, before any authentication
      // attempt and before the capability fallback is reachable: it has no registry account, so
      // this endpoint must never become a way for it to revoke or delete a customer. Refusing it
      // here also keeps it out of the fallback's "try the bearer as a deletion capability" path.
      const stated = request.headers
        .get("Authorization")
        ?.match(/^(Bearer|DPoP) ([A-Za-z0-9._-]+)$/)?.[2];
      if (env.MCP_AUTH_TOKEN && stated && equal(stated, env.MCP_AUTH_TOKEN))
        throw new HttpError(401, "customer_session_required");
      try {
        const principal = await control(request, env);
        tenant = principal.tenant;
        deletionTokenHash = principal.hash;
        const remainingSession = Math.max(1, principal.exp - now());
        retryTtl = Math.min(remainingSession, 60);
      } catch (err: any) {
        if (!(err instanceof HttpError)) throw err;
        // Server-side failures are never downgraded into a retry path.
        if (err.status >= 500) throw err;
        // A same-origin denial is a transport/CSRF decision, not an authentication failure:
        // it must never fall through to a capability path that performs the same deletion.
        if (err.status === 403 && err.code === "origin_denied") throw err;
        const authorization = request.headers.get("Authorization");
        const cookie = request.headers
          .get("Cookie")
          ?.split(";")
          .map((item) => item.trim())
          .find((item) => item.startsWith("agentsecret_session="))
          ?.slice("agentsecret_session=".length);
        const token =
          authorization?.match(/^(Bearer|DPoP) ([A-Za-z0-9._-]+)$/)?.[2] ||
          cookie;
        if (!token) throw err;
        let parsedTenant: string;
        let tokenHash: string;
        try {
          parsedTenant = referenceTenant(token, "as2");
          tokenHash = await hash(token);
          // The capability path is gated by the credential alone: the authority rejects every
          // hash that is not the live deletion capability, and it is never reached for a tenant
          // without registry state, so this cannot allocate or probe a Durable Object.
          await authority(env, parsedTenant, {
            op: "verify_deletion_credential",
            hash: tokenHash,
          });
        } catch (innerErr: any) {
          if (innerErr instanceof HttpError && innerErr.status >= 500) {
            throw innerErr;
          }
          // Unknown tenant, forged token and expired capability are indistinguishable.
          throw new HttpError(401, "unauthorized");
        }
        tenant = parsedTenant;
        deletionTokenHash = tokenHash;
      }

      // Account deletion is scoped to real customer accounts persisted in the registry.
      // Configured legacy tenants (for example the operator tenant "default") have authority
      // state but no customer account row, so an authenticated control session must never be
      // able to tombstone or revoke them through this endpoint.
      if (!env.DB) throw new HttpError(503, "database_unavailable");
      const existingAccount = await findAccountById(env.DB, tenant);
      const alreadyDeleted = existingAccount
        ? false
        : await isAccountTombstoned(env.DB, tenant);
      if (!existingAccount && !alreadyDeleted) {
        throw new HttpError(403, "customer_account_required");
      }

      await deleteCustomerAccount(env, tenant, deletionTokenHash, retryTtl);
      const response = json({ success: true, deleted: true });
      response.headers.set("Set-Cookie", clearSessionCookie());
      return response;
    }
  }
  if (path === "/api/user/audit" && request.method === "GET") {
    return customerRoute(request, env, async ({ principal }) =>
      json({
        logs: await authority(env, principal.tenant, {
          op: "audit",
          principal,
        }),
      }),
    );
  }
  if (
    (path === "/oauth/revoke" || path === "/api/user/revoke") &&
    request.method === "POST"
  ) {
    // `/api/user/revoke` is the customer's own revocation surface and requires a customer
    // session; `/oauth/revoke` is the agent-facing AS endpoint and keeps accepting any control
    // principal (a CLI revoking a grant it holds). Neither can name another account: the tenant is
    // the principal's, so a bootstrap credential only ever touches its own legacy tenant.
    const revoke = async (principal: Principal) => {
      const input = await body(request);
      if (
        input.grantId &&
        (typeof input.grantId !== "string" ||
          !/^[\w-]{43}$/.test(input.grantId))
      )
        throw new HttpError(400, "invalid_grant_id");
      await authority(env, principal.tenant, {
        op: "revoke",
        principal,
        hash: input.grantId,
      });
      return json({ success: true });
    };
    if (path === "/api/user/revoke")
      return customerRoute(request, env, ({ principal }) => revoke(principal));
    return revoke(await control(request, env));
  }
  if (
    path.startsWith("/api/") ||
    path.startsWith("/oauth/") ||
    path.startsWith("/.well-known/")
  )
    throw new HttpError(404, "not_found");
  if (request.method === "GET" && adapters.assets.available())
    return adapters.assets.fetch(request);
  throw new HttpError(404, "not_found");
}

/**
 * Handle one request through the application core.
 *
 * The environment is adapted exactly once per request, and only after the
 * registry backend has been chosen, so the whole request path sees one
 * database adapter. This is the seam both hosts call: a Cloudflare Worker's
 * `fetch` handler and a Node server's request handler both end here, which is
 * what makes the two deployments one application rather than two forks.
 */
export async function handleApplicationRequest(
  input: ApplicationRequest,
): Promise<Response> {
  let env: Env = input.env;
  try {
    const registryEnv = withRegistryDatabase(input.env);
    env = Object.create(registryEnv) as Env;
    env.SECURITY = {
      getByName(tenant: string) {
        return {
          dispatch: (command: unknown) =>
            input.adapters.authority.dispatch(tenant, command),
        };
      },
    } as Env["SECURITY"];
    return await routes(input.request, env, input.adapters);
  } catch (error) {
    const httpError =
      error instanceof HttpError ? error : new HttpError(500, "internal_error");
    const response = json({ error: httpError.code }, httpError.status);
    if (httpError.status === 401)
      response.headers.set(
        "WWW-Authenticate",
        `DPoP resource_metadata="${env.PUBLIC_ORIGIN || new URL(input.request.url).origin}/.well-known/oauth-protected-resource"`,
      );
    return response;
  }
}
