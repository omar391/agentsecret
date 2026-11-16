import { createHash, timingSafeEqual } from "node:crypto";
import {
  BrowserGrantError,
  BrowserGrantLedger,
  type BrowserActionRequest,
  type BrowserReceipt,
} from "./grant";
import type { BrowserFillReceipt } from "./driver";

export interface BrowserFillDriver {
  fill(input: {
    origin: string;
    selector: string;
    value: string;
    authorizeDispatch?: () => void;
  }): Promise<BrowserFillReceipt>;
  fillTotp(input: {
    origin: string;
    selector: string;
    secret: string;
    atMilliseconds: number | (() => number);
    authorizeDispatch?: () => void;
  }): Promise<BrowserFillReceipt>;
  read(input: {
    origin: string;
    selector: string;
    authorizeDispatch?: () => void;
  }): Promise<string>;
  ensure(input: {
    origin: string;
    selector: string;
    value: string;
    authorizeDispatch(): void;
  }): Promise<{ unchanged: boolean; verified: boolean }>;
}

export interface ResolvedBrowserMaterial {
  origin: string;
  selector: string;
  value: string;
}

export interface ResolvedBrowserTotpMaterial {
  origin: string;
  selector: string;
  secret: string;
}

export interface ResolvedBrowserField {
  origin: string;
  selector: string;
}

export type BrowserExecutionStatus =
  "filled" | "filled_totp" | "captured" | "unchanged" | "updated" | "verified";

export interface BrowserExecutionResult {
  receipt: BrowserReceipt;
  result: BrowserExecutionStatus;
  reference?: string;
  verified?: boolean;
}

export class BrowserExecutionError extends Error {
  constructor(
    readonly code:
      | "resolved_binding_mismatch"
      | "resolved_material_invalid"
      | "action_not_supported"
      | "grant_expired"
      | "action_cancelled",
  ) {
    super(code);
  }
}

function requireString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0)
    throw new BrowserExecutionError("resolved_material_invalid");
  return value;
}

function checkBinding(
  receipt: BrowserReceipt,
  material: { origin: string; selector: string },
): { origin: string; selector: string } {
  const origin = requireString(material?.origin);
  const selector = requireString(material?.selector);
  if (origin.toLowerCase() !== receipt.origin)
    throw new BrowserExecutionError("resolved_binding_mismatch");
  if (receipt.fieldSelector !== null && selector !== receipt.fieldSelector)
    throw new BrowserExecutionError("resolved_binding_mismatch");
  return { origin, selector };
}

function valuesEqual(left: string, right: string): boolean {
  const a = createHash("sha256").update(left, "utf8").digest();
  const b = createHash("sha256").update(right, "utf8").digest();
  return timingSafeEqual(a, b);
}

/**
 * Redeem exactly one grant and then invoke the driver. Resolution happens only
 * after redemption; the result contains the guarded receipt and status, never
 * the material, TOTP code or a comparison value.
 */
export async function executeBrowserAction(options: {
  ledger: Pick<BrowserGrantLedger, "redeem">;
  request: BrowserActionRequest;
  atMilliseconds: number;
  clock?: () => number;
  onProtectedDispatch?: () => void;
  driver: BrowserFillDriver;
  resolveFill: (receipt: BrowserReceipt) => Promise<ResolvedBrowserMaterial>;
  resolveTotp: (
    receipt: BrowserReceipt,
  ) => Promise<ResolvedBrowserTotpMaterial>;
  resolveCapture: (receipt: BrowserReceipt) => Promise<ResolvedBrowserField>;
  storeCaptured: (
    receipt: BrowserReceipt,
    value: string,
    authorizeDispatch: () => void,
  ) => Promise<{ reference: string; verified: boolean }>;
  resolveDesired: (receipt: BrowserReceipt) => Promise<ResolvedBrowserMaterial>;
  signal?: AbortSignal;
}): Promise<BrowserExecutionResult> {
  const receipt = options.ledger.redeem(
    options.request,
    options.atMilliseconds,
  );
  const authorizeDispatch = (): void => {
    if (options.signal?.aborted)
      throw new BrowserExecutionError("action_cancelled");
    assertGrantLive(receipt, options);
    options.onProtectedDispatch?.();
  };
  if (receipt.kind === "fill") {
    const material = await options.resolveFill(receipt);
    const { origin, selector } = checkBinding(receipt, material);
    const value = requireString(material?.value);
    const result = await options.driver.fill({
      origin,
      selector,
      value,
      authorizeDispatch,
    });
    return { receipt, result: result.status };
  }
  if (receipt.kind === "totp") {
    const material = await options.resolveTotp(receipt);
    const { origin, selector } = checkBinding(receipt, material);
    const secret = requireString(material?.secret);
    const result = await options.driver.fillTotp({
      origin,
      selector,
      secret,
      atMilliseconds: () => {
        authorizeDispatch();
        return options.clock?.() ?? options.atMilliseconds;
      },
      authorizeDispatch,
    });
    return { receipt, result: result.status };
  }
  if (receipt.kind === "capture") {
    const field = await options.resolveCapture(receipt);
    const { origin, selector } = checkBinding(receipt, field);
    const value = await options.driver.read({
      origin,
      selector,
      authorizeDispatch,
    });
    assertGrantLive(receipt, options);
    const stored = await options.storeCaptured(
      receipt,
      value,
      authorizeDispatch,
    );
    return {
      receipt,
      result: "captured",
      reference: requireString(stored?.reference),
      verified: stored.verified === true,
    };
  }
  if (receipt.kind === "verify") {
    const material = await options.resolveDesired(receipt);
    const { origin, selector } = checkBinding(receipt, material);
    const desired = requireString(material?.value);
    const current = await options.driver.read({
      origin,
      selector,
      authorizeDispatch,
    });
    return {
      receipt,
      result: "verified",
      verified: valuesEqual(current, desired),
    };
  }
  if (receipt.kind === "ensure") {
    const material = await options.resolveDesired(receipt);
    const { origin, selector } = checkBinding(receipt, material);
    const desired = requireString(material?.value);
    const outcome = await options.driver.ensure({
      origin,
      selector,
      value: desired,
      authorizeDispatch,
    });
    return {
      receipt,
      result: outcome.unchanged ? "unchanged" : "updated",
      verified: outcome.verified,
    };
  }
  throw new BrowserExecutionError("action_not_supported");
}

function assertGrantLive(
  receipt: BrowserReceipt,
  options: { clock?: () => number; atMilliseconds: number },
): void {
  const now = options.clock?.() ?? options.atMilliseconds;
  if (!Number.isFinite(now) || now >= receipt.expiresAt)
    throw new BrowserExecutionError("grant_expired");
}

export function isBrowserGrantError(
  error: unknown,
): error is BrowserGrantError {
  return error instanceof BrowserGrantError;
}
