import { join } from "node:path";
import {
  BrowserActionError,
  runBrowserAction,
  type BrowserActionDeps,
} from "./browser/action";
import { BrowserActionReceiptStore } from "./browser/receipt-store";

/** A value-free managed browser-action request parsed from `run browser`. */
export interface ManagedBrowserAction {
  kind: "browser";
  grantId: string;
  action: string;
  origin: string;
  fieldSelector: string;
  reference: string;
  url?: string;
}

export interface ManagedBrowserRunReceipt {
  schema: "agentsecret.run/browser/v1";
  status: "completed" | "failed";
  action?:
    | "filled"
    | "filled_totp"
    | "captured"
    | "unchanged"
    | "updated"
    | "verified";
  grantId?: string;
  origin?: string;
  fieldSelector?: string;
  reference?: string;
  verified?: boolean;
  reason?: string;
}

const MANAGED_FLAGS = new Set([
  "--grant",
  "--kind",
  "--origin",
  "--selector",
  "--reference",
  "--url",
  "--receipt-dir",
]);

const MANAGED_REQUIRED = [
  "--grant",
  "--kind",
  "--origin",
  "--selector",
  "--reference",
] as const;

/**
 * Parse `agentsecret run browser` arguments into a value-free action
 * request with no positional or unknown flag surface.
 */
export function parseManagedBrowserArgs(args: string[]): ManagedBrowserAction {
  if (args[0] !== "browser")
    throw new BrowserActionError("invalid_browser_action_request");
  const rest = args.slice(1);
  const values: Record<string, string> = {};
  const seen = new Set<string>();
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    if (!MANAGED_FLAGS.has(flag))
      throw new BrowserActionError("invalid_browser_action_request");
    if (seen.has(flag))
      throw new BrowserActionError("invalid_browser_action_request");
    seen.add(flag);
    const value = rest[index + 1];
    if (value === undefined || value === "" || value.startsWith("--"))
      throw new BrowserActionError("invalid_browser_action_request");
    values[flag.slice(2)] = value;
  }
  for (const flag of MANAGED_REQUIRED) {
    if (!seen.has(flag))
      throw new BrowserActionError("invalid_browser_action_request");
  }
  return {
    kind: "browser",
    grantId: values.grant,
    action: values.kind,
    origin: values.origin,
    fieldSelector: values.selector,
    reference: values.reference,
    ...(values.url === undefined ? {} : { url: values.url }),
  };
}

export async function runManagedBrowserAction(
  action: ManagedBrowserAction,
  deps: Omit<BrowserActionDeps, "receipts"> & { receiptDirectory: string },
): Promise<ManagedBrowserRunReceipt> {
  const body = {
    grantId: action.grantId,
    kind: action.action,
    origin: action.origin,
    fieldSelector: action.fieldSelector,
    reference: action.reference,
    ...(action.url === undefined ? {} : { url: action.url }),
  };
  const receipts = new BrowserActionReceiptStore(deps.receiptDirectory);
  try {
    const receipt = await runBrowserAction(body, {
      ...deps,
      executor: deps.executor,
      accountId: deps.accountId,
      server: deps.server,
      fetchImpl: deps.fetchImpl,
      signal: deps.signal,
      receipts,
      now: deps.now,
      launchDriver: deps.launchDriver,
      resolveSecret: deps.resolveSecret,
      storeCaptured: deps.storeCaptured,
    });
    return {
      schema: "agentsecret.run/browser/v1",
      status: "completed",
      action: receipt.action,
      grantId: receipt.grantId,
      origin: receipt.origin,
      fieldSelector: receipt.fieldSelector,
      ...(receipt.reference === undefined
        ? {}
        : { reference: receipt.reference }),
      ...(receipt.verified === undefined ? {} : { verified: receipt.verified }),
    };
  } catch (error) {
    if (deps.signal?.aborted) throw error;
    const reason =
      error instanceof Error && /^[a-z0-9_]{1,80}$/u.test(error.message)
        ? error.message
        : "browser_action_failed";
    return {
      schema: "agentsecret.run/browser/v1",
      status: "failed",
      reason,
    };
  }
}

export function managedBrowserReceiptDirectory(
  configDir: string,
  requested?: string,
): string {
  return requested ?? join(configDir, "browser-actions");
}
