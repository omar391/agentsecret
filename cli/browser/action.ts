import { hash } from "../../src/security/primitives";
import { browserGrantTenant } from "../../src/security/browser-grant";
import { BrowserDriverError } from "./driver";
import {
  BrowserExecutionError,
  executeBrowserAction,
  type BrowserFillDriver,
} from "./execute";
import { executorProof, type ExecutorIdentityRecord } from "./executor";
import {
  BrowserGrantError,
  type BrowserActionKind,
  type BrowserActionRequest,
  type BrowserReceipt,
} from "./grant";
import {
  BrowserActionReceiptStore,
  browserActionRequestDigest,
  type SafeBrowserActionReceipt,
} from "./receipt-store";

export class BrowserActionError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

/**
 * A failure that provably happened before any protected material reached the
 * page or vault: resolution refusals, binding checks and grant checks. The
 * receipt store records these as rejected; anything thrown later is recorded
 * as an unknown outcome and is never blindly repeated.
 */
export class BrowserActionSetupError extends Error {
  constructor(cause: Error) {
    super(cause.message);
  }
}

const GUARDED_PROVIDER_ITEM_METHODS = new Set([
  "create",
  "get",
  "getAll",
  "list",
  "put",
]);

/** Preserve SDK method receivers while guarding each protected item dispatch. */
export function guardServiceAccountClient<T extends { items: object }>(
  client: T,
  authorizeDispatch?: () => void,
): T {
  return new Proxy(client, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (property !== "items" || !value || typeof value !== "object")
        return value;
      return new Proxy(value, {
        get(items, method) {
          const operation = Reflect.get(items, method, items);
          if (typeof operation !== "function") return operation;
          return (...args: unknown[]) => {
            if (GUARDED_PROVIDER_ITEM_METHODS.has(String(method)))
              authorizeDispatch?.();
            return Reflect.apply(operation, items, args);
          };
        },
      });
    },
  });
}

export interface BrowserActionInput {
  grantId: string;
  kind: string;
  origin: string;
  fieldSelector: string;
  reference: string;
  url?: string;
}

export interface BrowserActionFetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export interface BrowserActionDeps {
  executor: ExecutorIdentityRecord;
  accountId: string;
  server: string;
  fetchImpl: (
    url: string,
    init: {
      method: string;
      headers: Record<string, string>;
      body: string;
    },
  ) => Promise<BrowserActionFetchResponse>;
  signal?: AbortSignal;
  receipts: BrowserActionReceiptStore;
  now: () => number;
  launchDriver: (input: {
    url: string;
    origin: string;
  }) => Promise<{ driver: BrowserFillDriver; close(): Promise<void> | void }>;
  resolveSecret: (input: {
    alias: string;
    reference: string;
  }) => Promise<string>;
  storeCaptured: (input: {
    alias: string;
    reference: string;
    value: string;
    authorizeDispatch: () => void;
  }) => Promise<{ reference: string; verified: boolean }>;
}

const ACTION_KINDS = new Set<BrowserActionKind>([
  "fill",
  "totp",
  "capture",
  "verify",
  "ensure",
]);

function safeCode(error: unknown, fallback: string): string {
  if (error instanceof Error && /^[a-z0-9_]{1,80}$/u.test(error.message))
    return error.message;
  return fallback;
}

function boundedField(value: unknown, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  )
    throw new BrowserActionError("invalid_browser_action_request");
  return value;
}

function normalizedOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new BrowserActionError("invalid_browser_action_request");
  }
  const local =
    parsed.hostname === "localhost" ||
    parsed.hostname === "127.0.0.1" ||
    parsed.hostname === "[::1]";
  if (
    (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:")) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    parsed.pathname !== "/"
  )
    throw new BrowserActionError("invalid_browser_action_request");
  return parsed.origin.toLowerCase();
}

function normalizedPageUrl(value: string, origin: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new BrowserActionError("invalid_browser_action_request");
  }
  if (
    parsed.username ||
    parsed.password ||
    parsed.origin.toLowerCase() !== origin
  )
    throw new BrowserActionError("invalid_browser_action_request");
  return parsed.href;
}

function serverReceipt(
  value: unknown,
  request: BrowserActionRequest,
): BrowserReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new BrowserActionError("redeem_receipt_invalid");
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !==
      "alias,expiresAt,fieldSelector,grantId,kind,origin,status" ||
    record.status !== "authorized" ||
    record.grantId !== request.grantId ||
    typeof record.alias !== "string" ||
    !/^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(record.alias) ||
    record.origin !== request.origin ||
    record.kind !== request.kind ||
    record.fieldSelector !== request.fieldSelector ||
    !Number.isSafeInteger(record.expiresAt)
  )
    throw new BrowserActionError("redeem_receipt_invalid");
  return {
    status: "authorized",
    grantId: request.grantId,
    alias: record.alias,
    origin: request.origin,
    kind: request.kind,
    fieldSelector: request.fieldSelector,
    expiresAt: (record.expiresAt as number) * 1000,
  };
}

/**
 * Consume one owner-issued browser grant end to end: redeem it on the broker
 * with the enrolled executor proof, resolve the bound secret privately, act on
 * the attached page and return the value-free receipt. The durable receipt
 * store makes retries idempotent and uncertain outcomes permanently closed.
 */
export async function runBrowserAction(
  input: BrowserActionInput,
  deps: BrowserActionDeps,
): Promise<SafeBrowserActionReceipt> {
  try {
    browserGrantTenant(input.grantId);
  } catch {
    throw new BrowserActionError("invalid_browser_action_request");
  }
  const origin = normalizedOrigin(input.origin);
  if (!ACTION_KINDS.has(input.kind as BrowserActionKind))
    throw new BrowserActionError("invalid_browser_action_request");
  const kind = input.kind as BrowserActionKind;
  const fieldSelector = boundedField(input.fieldSelector, 1024);
  const reference = boundedField(input.reference, 2048);
  const url = normalizedPageUrl(input.url ?? origin + "/", origin);
  const tenantSegment = Buffer.from(deps.accountId, "utf8").toString(
    "base64url",
  );
  if (input.grantId.split(".")[1] !== tenantSegment)
    throw new BrowserActionError("browser_grant_account_mismatch");

  const request: BrowserActionRequest = {
    grantId: input.grantId,
    accountId: deps.accountId,
    origin,
    kind,
    fieldSelector,
  };
  const digest = browserActionRequestDigest({
    ...request,
    reference,
    url,
  });
  const saved = deps.receipts.begin(request.grantId, digest);
  if (saved) return saved;
  let protectedDispatchStarted = false;

  const launched = await deps
    .launchDriver({ url, origin })
    .catch((error: unknown) => {
      deps.receipts.reject(request.grantId, digest);
      if (deps.signal?.aborted) throw error;
      throw new BrowserActionError(safeCode(error, "browser_launch_failed"));
    });
  try {
    const bodyText = JSON.stringify(request);
    const response = await deps
      .fetchImpl(deps.server + "/api/executor/grants/redeem", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          DPoP: await executorProof(
            deps.executor,
            "POST",
            deps.server + "/api/executor/grants/redeem",
            undefined,
            await hash(bodyText),
          ),
        },
        body: bodyText,
      })
      .catch((error: unknown) => {
        deps.receipts.markUnknown(request.grantId, digest);
        if (deps.signal?.aborted) throw error;
        throw new BrowserActionError("browser_grant_redeem_outcome_unknown");
      });
    if (!response.ok) {
      let reason = "browser_grant_redeem_denied";
      try {
        const body = (await response.json()) as { error?: unknown };
        if (
          typeof body?.error === "string" &&
          /^[a-z0-9_]{1,80}$/u.test(body.error)
        )
          reason = body.error;
      } catch {}
      deps.receipts.reject(request.grantId, digest);
      throw new BrowserActionError(reason);
    }
    const receipt = await response
      .json()
      .then((value) => serverReceipt(value, request))
      .catch((error: unknown) => {
        deps.receipts.markUnknown(request.grantId, digest);
        if (deps.signal?.aborted) throw error;
        throw new BrowserActionError("browser_grant_redeem_outcome_unknown");
      });
    const expiresAt = receipt.expiresAt;
    const ledger = {
      redeem(
        action: BrowserActionRequest,
        atMilliseconds: number,
      ): BrowserReceipt {
        if (action.grantId !== receipt.grantId)
          throw new BrowserGrantError("grant_unknown");
        if (action.accountId !== request.accountId)
          throw new BrowserGrantError("account_mismatch");
        if (normalizedOrigin(action.origin) !== receipt.origin)
          throw new BrowserGrantError("origin_mismatch");
        if (action.kind !== receipt.kind)
          throw new BrowserGrantError("action_not_granted");
        if (action.fieldSelector !== receipt.fieldSelector)
          throw new BrowserGrantError("field_mismatch");
        if (!Number.isFinite(atMilliseconds) || atMilliseconds >= expiresAt)
          throw new BrowserGrantError("grant_expired");
        return receipt;
      },
    };
    const setup = <T>(pending: Promise<T>): Promise<T> =>
      pending.catch((error: unknown) => {
        throw error instanceof BrowserActionSetupError
          ? error
          : new BrowserActionSetupError(
              error instanceof Error
                ? error
                : new Error("browser_action_setup_failed"),
            );
      });
    const result = await executeBrowserAction({
      ledger,
      request,
      atMilliseconds: deps.now(),
      clock: deps.now,
      onProtectedDispatch: () => {
        protectedDispatchStarted = true;
      },
      signal: deps.signal,
      driver: launched.driver,
      resolveFill: (bound) =>
        setup(
          deps
            .resolveSecret({ alias: bound.alias, reference })
            .then((value) => ({
              origin: bound.origin,
              selector: bound.fieldSelector ?? fieldSelector,
              value,
            })),
        ),
      resolveTotp: (bound) =>
        setup(
          deps
            .resolveSecret({ alias: bound.alias, reference })
            .then((secret) => ({
              origin: bound.origin,
              selector: bound.fieldSelector ?? fieldSelector,
              secret,
            })),
        ),
      resolveCapture: (bound) =>
        Promise.resolve({
          origin: bound.origin,
          selector: bound.fieldSelector ?? fieldSelector,
        }),
      storeCaptured: (bound, value, authorizeDispatch) => {
        authorizeDispatch();
        return deps.storeCaptured({
          alias: bound.alias,
          reference,
          value,
          authorizeDispatch,
        });
      },
      resolveDesired: (bound) =>
        setup(
          deps
            .resolveSecret({ alias: bound.alias, reference })
            .then((value) => ({
              origin: bound.origin,
              selector: bound.fieldSelector ?? fieldSelector,
              value,
            })),
        ),
    });
    const safe: SafeBrowserActionReceipt = {
      status: "completed",
      grantId: request.grantId,
      action: result.result,
      origin: receipt.origin,
      fieldSelector: receipt.fieldSelector ?? fieldSelector,
      ...(result.reference === undefined
        ? {}
        : { reference: result.reference }),
      ...(result.verified === undefined ? {} : { verified: result.verified }),
    };
    deps.receipts.finish(request.grantId, digest, safe);
    return safe;
  } catch (error) {
    if (error instanceof BrowserActionError) {
      // Inner branches already recorded the rejection or unknown outcome.
    } else if (error instanceof BrowserDriverError) {
      if (protectedDispatchStarted)
        deps.receipts.markUnknown(request.grantId, digest);
      else deps.receipts.reject(request.grantId, digest);
    } else if (protectedDispatchStarted) {
      deps.receipts.markUnknown(request.grantId, digest);
    } else if (
      error instanceof BrowserActionSetupError ||
      error instanceof BrowserExecutionError ||
      error instanceof BrowserGrantError
    ) {
      deps.receipts.reject(request.grantId, digest);
    } else {
      deps.receipts.markUnknown(request.grantId, digest);
    }
    if (deps.signal?.aborted) throw error;
    if (error instanceof BrowserActionError) throw error;
    throw new BrowserActionError(safeCode(error, "browser_action_failed"));
  } finally {
    try {
      await launched.close();
    } catch {
      // Teardown failures never rewrite a recorded action outcome.
    }
  }
}
