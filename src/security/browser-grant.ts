import { HttpError, isWellFormedUnicode, referenceTenant } from "./primitives";

export const BROWSER_ACTION_KINDS = [
  "fill",
  "totp",
  "capture",
  "verify",
  "ensure",
] as const;

export type BrowserActionKind = (typeof BROWSER_ACTION_KINDS)[number];

export interface BrowserGrantRecord {
  grantId: string;
  accountId: string;
  executorId: string;
  executorThumbprint: string;
  alias: string;
  origin: string;
  kinds: BrowserActionKind[];
  fieldSelector: string;
  policyBinding: string;
  epoch: number;
  expiresAt: number;
  redeemedAt: number | null;
  revokedAt: number | null;
}

export interface BrowserGrantIssue {
  executorId: string;
  alias: string;
  origin: string;
  kinds: BrowserActionKind[];
  fieldSelector: string;
  expiresAt: number;
}

export interface BrowserGrantAction {
  grantId: string;
  accountId: string;
  origin: string;
  kind: BrowserActionKind;
  fieldSelector: string;
}

export interface BrowserGrantReceipt {
  status: "authorized";
  grantId: string;
  alias: string;
  origin: string;
  kind: BrowserActionKind;
  fieldSelector: string;
  expiresAt: number;
}

export type BrowserGrantView = Pick<
  BrowserGrantRecord,
  | "grantId"
  | "accountId"
  | "executorId"
  | "alias"
  | "origin"
  | "kinds"
  | "fieldSelector"
  | "expiresAt"
  | "redeemedAt"
  | "revokedAt"
>;

const GRANT_KEYS = [
  "alias",
  "executorId",
  "expiresIn",
  "fieldSelector",
  "kinds",
  "origin",
] as const;
const ACTION_KEYS = [
  "accountId",
  "fieldSelector",
  "grantId",
  "kind",
  "origin",
] as const;

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[],
): void {
  const keys = Object.keys(value);
  if (
    keys.some((key) => !allowed.includes(key)) ||
    required.some((key) => !Object.hasOwn(value, key))
  )
    throw new HttpError(400, "invalid_browser_grant");
}

function boundedText(
  value: unknown,
  maximum: number,
  pattern?: RegExp,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    !isWellFormedUnicode(value) ||
    /[\u0000-\u001f\u007f]/.test(value) ||
    (pattern && !pattern.test(value))
  )
    throw new HttpError(400, "invalid_browser_grant");
  return value;
}

/** Normalize only an exact HTTPS origin (or an explicit local development origin). */
export function browserGrantOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048)
    throw new HttpError(400, "invalid_browser_grant");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new HttpError(400, "invalid_browser_grant");
  }
  const local =
    parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (
    (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:")) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    parsed.pathname !== "/"
  )
    throw new HttpError(400, "invalid_browser_grant");
  return parsed.origin.toLowerCase();
}

/** A browser origin must be inside the current alias policy's exact domain set. */
export function browserGrantOriginAllowed(
  origin: string,
  allowedDomains: readonly string[],
): boolean {
  const host = new URL(origin).hostname.toLowerCase();
  return allowedDomains.some((entry) => {
    const domain = entry.toLowerCase();
    if (!domain.startsWith("*.")) return host === domain;
    const suffix = domain.slice(2);
    return host !== suffix && host.endsWith("." + suffix);
  });
}

export function browserGrantTenant(grantId: unknown): string {
  try {
    return referenceTenant(grantId, "bg1");
  } catch (error) {
    if (error instanceof HttpError && error.status >= 500) throw error;
    throw new HttpError(400, "invalid_browser_grant");
  }
}

/** Parse the owner's exact grant request. Extra fields and unknown actions fail closed. */
export function parseBrowserGrantIssue(
  input: Record<string, unknown>,
  at: number,
): BrowserGrantIssue {
  exactKeys(input, GRANT_KEYS, [
    "alias",
    "executorId",
    "fieldSelector",
    "kinds",
    "origin",
  ]);
  const executorId = boundedText(
    input.executorId,
    47,
    /^exe_[A-Za-z0-9_-]{43}$/u,
  );
  const alias = boundedText(input.alias, 64, /^[A-Za-z][A-Za-z0-9_]{0,63}$/u);
  const fieldSelector = boundedText(input.fieldSelector, 1024);
  if (!Array.isArray(input.kinds) || input.kinds.length === 0)
    throw new HttpError(400, "invalid_browser_grant");
  const requestedKinds = input.kinds.map((kind) => boundedText(kind, 16));
  if (
    requestedKinds.some(
      (kind) => !BROWSER_ACTION_KINDS.includes(kind as BrowserActionKind),
    )
  )
    throw new HttpError(400, "invalid_browser_grant");
  const kinds = [...new Set(requestedKinds)] as BrowserActionKind[];
  const expiresIn =
    input.expiresIn === undefined ? 60 : Number(input.expiresIn);
  if (!Number.isSafeInteger(expiresIn) || expiresIn < 5 || expiresIn > 300)
    throw new HttpError(400, "invalid_browser_grant");
  return {
    executorId,
    alias,
    origin: browserGrantOrigin(input.origin),
    kinds,
    fieldSelector,
    expiresAt: at + expiresIn,
  };
}

/** Parse the executor's exact action request; the grant ID remains the routing key. */
export function parseBrowserGrantAction(
  input: Record<string, unknown>,
): BrowserGrantAction {
  exactKeys(input, ACTION_KEYS, ACTION_KEYS);
  const grantId = boundedText(input.grantId, 256);
  const accountId = boundedText(input.accountId, 80, /^[A-Za-z0-9_-]{1,80}$/u);
  const kind = boundedText(input.kind, 16);
  if (!BROWSER_ACTION_KINDS.includes(kind as BrowserActionKind))
    throw new HttpError(400, "invalid_browser_grant");
  return {
    grantId,
    accountId,
    origin: browserGrantOrigin(input.origin),
    kind: kind as BrowserActionKind,
    fieldSelector: boundedText(input.fieldSelector, 1024),
  };
}

export function parseBrowserGrantRevocation(
  input: Record<string, unknown>,
): string {
  exactKeys(input, ["grantId"], ["grantId"]);
  return boundedText(input.grantId, 256);
}

export function browserGrantReceipt(
  grant: BrowserGrantRecord,
  kind: BrowserActionKind,
): BrowserGrantReceipt {
  return {
    status: "authorized",
    grantId: grant.grantId,
    alias: grant.alias,
    origin: grant.origin,
    kind,
    fieldSelector: grant.fieldSelector,
    expiresAt: grant.expiresAt,
  };
}

export function browserGrantView(grant: BrowserGrantRecord): BrowserGrantView {
  return {
    grantId: grant.grantId,
    accountId: grant.accountId,
    executorId: grant.executorId,
    alias: grant.alias,
    origin: grant.origin,
    kinds: grant.kinds,
    fieldSelector: grant.fieldSelector,
    expiresAt: grant.expiresAt,
    redeemedAt: grant.redeemedAt,
    revokedAt: grant.revokedAt,
  };
}
