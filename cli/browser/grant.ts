export type BrowserActionKind =
  "fill" | "totp" | "capture" | "verify" | "ensure";

export interface BrowserGrant {
  grantId: string;
  accountId: string;
  alias: string;
  origin: string;
  kinds: readonly BrowserActionKind[];
  expiresAt: number;
  redeemedAt: number | null;
  fieldSelector: string | null;
}

export interface BrowserActionRequest {
  grantId: string;
  accountId: string;
  origin: string;
  kind: BrowserActionKind;
  fieldSelector: string | null;
}

export interface BrowserReceipt {
  status: "authorized";
  grantId: string;
  alias: string;
  origin: string;
  kind: BrowserActionKind;
  fieldSelector: string | null;
  expiresAt: number;
}

export type BrowserGrantFailure =
  | "grant_unknown"
  | "grant_expired"
  | "grant_replayed"
  | "account_mismatch"
  | "origin_mismatch"
  | "action_not_granted"
  | "field_mismatch";

export class BrowserGrantError extends Error {
  constructor(readonly code: BrowserGrantFailure) {
    super(code);
  }
}

function normalizedOrigin(origin: string): string {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new BrowserGrantError("origin_mismatch");
  }
  const local =
    parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:"))
    throw new BrowserGrantError("origin_mismatch");
  if (parsed.username || parsed.password)
    throw new BrowserGrantError("origin_mismatch");
  return parsed.origin.toLowerCase();
}

/**
 * A single-use, account/origin/action/field-bound authorization. The caller
 * marks the grant redeemed atomically before resolving any secret material; a
 * failed redemption never exposes a value or a reason derived from one.
 */
export class BrowserGrantLedger {
  readonly #grants = new Map<string, BrowserGrant>();

  issue(grant: BrowserGrant): BrowserGrant {
    if (this.#grants.has(grant.grantId))
      throw new BrowserGrantError("grant_replayed");
    if (!Number.isFinite(grant.expiresAt) || grant.kinds.length === 0)
      throw new BrowserGrantError("action_not_granted");
    normalizedOrigin(grant.origin);
    this.#grants.set(grant.grantId, { ...grant, kinds: [...grant.kinds] });
    return grant;
  }

  redeem(
    request: BrowserActionRequest,
    atMilliseconds: number,
  ): BrowserReceipt {
    const grant = this.#grants.get(request.grantId);
    if (!grant) throw new BrowserGrantError("grant_unknown");
    if (grant.accountId !== request.accountId)
      throw new BrowserGrantError("account_mismatch");
    if (normalizedOrigin(request.origin) !== normalizedOrigin(grant.origin))
      throw new BrowserGrantError("origin_mismatch");
    if (!grant.kinds.includes(request.kind))
      throw new BrowserGrantError("action_not_granted");
    if (
      grant.fieldSelector !== null &&
      grant.fieldSelector !== request.fieldSelector
    )
      throw new BrowserGrantError("field_mismatch");
    if (!Number.isFinite(atMilliseconds) || atMilliseconds >= grant.expiresAt)
      throw new BrowserGrantError("grant_expired");
    if (grant.redeemedAt !== null)
      throw new BrowserGrantError("grant_replayed");
    const redeemed = { ...grant, redeemedAt: atMilliseconds };
    this.#grants.set(grant.grantId, redeemed);
    return {
      status: "authorized",
      grantId: grant.grantId,
      alias: grant.alias,
      origin: normalizedOrigin(grant.origin),
      kind: request.kind,
      fieldSelector: grant.fieldSelector,
      expiresAt: grant.expiresAt,
    };
  }

  get(grantId: string): BrowserGrant | null {
    const grant = this.#grants.get(grantId);
    return grant ? { ...grant } : null;
  }
}
