import { generateTotp, type TotpOptions } from "./totp";

export interface BrowserTransport {
  send(method: string, params: Record<string, unknown>): Promise<unknown>;
  close(): Promise<void> | void;
}

export interface BrowserFillReceipt {
  status: "filled" | "filled_totp";
  origin: string;
  selector: string;
}

export class BrowserDriverError extends Error {
  constructor(
    readonly code:
      | "browser_origin_mismatch"
      | "browser_frame_denied"
      | "browser_navigation_changed"
      | "browser_field_missing"
      | "browser_transport_error"
      | "browser_target_invalid",
  ) {
    super(code);
  }
}

function checkedOrigin(origin: string): string {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new BrowserDriverError("browser_target_invalid");
  }
  const local =
    parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:"))
    throw new BrowserDriverError("browser_target_invalid");
  if (parsed.username || parsed.password || parsed.search || parsed.hash)
    throw new BrowserDriverError("browser_target_invalid");
  return parsed.origin.toLowerCase();
}

function checkedSelector(selector: string): string {
  if (
    typeof selector !== "string" ||
    selector.length === 0 ||
    selector.length > 512
  )
    throw new BrowserDriverError("browser_target_invalid");
  return selector;
}

async function evaluate(
  transport: BrowserTransport,
  expression: string,
  contextId?: number,
): Promise<unknown> {
  let response: unknown;
  try {
    response = await transport.send("Runtime.evaluate", {
      expression,
      ...(contextId === undefined ? {} : { contextId }),
      returnByValue: true,
      awaitPromise: true,
    });
  } catch {
    throw new BrowserDriverError("browser_transport_error");
  }
  const result = response as {
    result?: { value?: unknown };
    exceptionDetails?: unknown;
  };
  if (result?.exceptionDetails)
    throw new BrowserDriverError("browser_transport_error");
  return result?.result?.value;
}

/**
 * Fill one already-authorized field in the currently attached page. The driver
 * verifies the live origin before touching the DOM and returns no value, length
 * or comparison result to its caller.
 */
export class BrowserDriver {
  constructor(private readonly transport: BrowserTransport) {}

  private async pageContext(origin: string): Promise<{
    frameId: string;
    loaderId: string;
    contextId: number;
  }> {
    let response: unknown;
    try {
      response = await this.transport.send("Page.getFrameTree", {});
    } catch {
      throw new BrowserDriverError("browser_transport_error");
    }
    const frameTree = (
      response as {
        frameTree?: {
          frame?: { id?: unknown; url?: unknown; loaderId?: unknown };
          childFrames?: unknown[];
        };
      }
    )?.frameTree;
    const frame = frameTree?.frame;
    if (
      !frameTree ||
      !frame ||
      typeof frame.id !== "string" ||
      typeof frame.url !== "string" ||
      typeof frame.loaderId !== "string"
    )
      throw new BrowserDriverError("browser_transport_error");
    if (frameTree.childFrames?.length)
      throw new BrowserDriverError("browser_frame_denied");
    let frameOrigin: string;
    try {
      frameOrigin = new URL(frame.url).origin.toLowerCase();
    } catch {
      throw new BrowserDriverError("browser_origin_mismatch");
    }
    if (frameOrigin !== origin)
      throw new BrowserDriverError("browser_origin_mismatch");

    let world: unknown;
    try {
      world = await this.transport.send("Page.createIsolatedWorld", {
        frameId: frame.id,
        worldName: "agentsecret-protected-operation",
        grantUniveralAccess: false,
      });
    } catch {
      throw new BrowserDriverError("browser_navigation_changed");
    }
    const contextId = (world as { executionContextId?: unknown })
      ?.executionContextId;
    if (!Number.isInteger(contextId))
      throw new BrowserDriverError("browser_navigation_changed");
    await this.confirmPage(origin, frame.id, frame.loaderId);
    return {
      frameId: frame.id,
      loaderId: frame.loaderId,
      contextId: contextId as number,
    };
  }

  private async confirmPage(
    origin: string,
    frameId: string,
    loaderId: string,
  ): Promise<void> {
    let response: unknown;
    try {
      response = await this.transport.send("Page.getFrameTree", {});
    } catch {
      throw new BrowserDriverError("browser_transport_error");
    }
    const frameTree = (
      response as {
        frameTree?: {
          frame?: { id?: unknown; url?: unknown; loaderId?: unknown };
          childFrames?: unknown[];
        };
      }
    )?.frameTree;
    const frame = frameTree?.frame;
    if (!frameTree || !frame || frameTree.childFrames?.length)
      throw new BrowserDriverError("browser_navigation_changed");
    let currentOrigin = "";
    try {
      currentOrigin = new URL(String(frame.url)).origin.toLowerCase();
    } catch {}
    if (
      frame.id !== frameId ||
      frame.loaderId !== loaderId ||
      currentOrigin !== origin
    )
      throw new BrowserDriverError("browser_navigation_changed");
  }

  async fill(input: {
    origin: string;
    selector: string;
    value: string;
    authorizeDispatch?: () => void;
  }): Promise<BrowserFillReceipt> {
    return this.fillValue(input, () => input.value);
  }

  private async fillValue(
    input: {
      origin: string;
      selector: string;
      authorizeDispatch?: () => void;
    },
    value: () => string,
    contextOverride?: { frameId: string; loaderId: string; contextId: number },
  ): Promise<BrowserFillReceipt> {
    const wanted = checkedOrigin(input.origin);
    const selector = checkedSelector(input.selector);
    const context = contextOverride ?? (await this.pageContext(wanted));
    input.authorizeDispatch?.();
    const safeValue = value();
    const status = await evaluate(
      this.transport,
      `(() => { const __agentsecret = "FILL"; if (location.origin.toLowerCase() !== ${JSON.stringify(wanted)}) return "origin"; if (window !== window.top || document.querySelector("iframe,frame")) return "frame"; const el = document.querySelector(${JSON.stringify(selector)}); if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) return "field"; if (el instanceof HTMLInputElement && ["button","checkbox","file","hidden","image","radio","reset","submit"].includes(el.type.toLowerCase())) return "field"; const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set; if (!setter) return "field"; setter.call(el, ${JSON.stringify(safeValue)}); el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" })); el.dispatchEvent(new Event("change", { bubbles: true })); return "filled"; })()`,
      context.contextId,
    );
    if (status === "origin")
      throw new BrowserDriverError("browser_origin_mismatch");
    if (status === "frame")
      throw new BrowserDriverError("browser_frame_denied");
    if (status !== "filled")
      throw new BrowserDriverError("browser_field_missing");
    await this.confirmPage(wanted, context.frameId, context.loaderId);
    return { status: "filled", origin: wanted, selector };
  }

  /** Read one approved field into memory. The value is returned only to the executor; never log it. */
  async read(input: {
    origin: string;
    selector: string;
    authorizeDispatch?: () => void;
  }): Promise<string> {
    const wanted = checkedOrigin(input.origin);
    const selector = checkedSelector(input.selector);
    const context = await this.pageContext(wanted);
    input.authorizeDispatch?.();
    const observed = await evaluate(
      this.transport,
      `(() => { const __agentsecret = "READ"; if (location.origin.toLowerCase() !== ${JSON.stringify(wanted)}) return null; if (window !== window.top || document.querySelector("iframe,frame")) return null; const el = document.querySelector(${JSON.stringify(selector)}); if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) return null; if (el instanceof HTMLInputElement && ["button","checkbox","file","hidden","image","radio","reset","submit"].includes(el.type.toLowerCase())) return null; return typeof el.value === "string" ? el.value : null; })()`,
      context.contextId,
    );
    if (typeof observed !== "string")
      throw new BrowserDriverError("browser_field_missing");
    await this.confirmPage(wanted, context.frameId, context.loaderId);
    return observed;
  }

  async fillTotp(input: {
    origin: string;
    selector: string;
    secret: string;
    atMilliseconds: number | (() => number);
    authorizeDispatch?: () => void;
    totp?: TotpOptions;
  }): Promise<BrowserFillReceipt> {
    const receipt = await this.fillValue(
      { ...input, authorizeDispatch: input.authorizeDispatch },
      () =>
        generateTotp(
          input.secret,
          typeof input.atMilliseconds === "function"
            ? input.atMilliseconds()
            : input.atMilliseconds,
          input.totp,
        ),
    );
    return { ...receipt, status: "filled_totp" };
  }

  async ensure(input: {
    origin: string;
    selector: string;
    value: string;
    authorizeDispatch(): void;
  }): Promise<{ unchanged: boolean; verified: boolean }> {
    const wanted = checkedOrigin(input.origin);
    const selector = checkedSelector(input.selector);
    const context = await this.pageContext(wanted);
    input.authorizeDispatch();
    const current = await this.evaluateField(context, wanted, selector, "READ");
    await this.confirmPage(wanted, context.frameId, context.loaderId);
    if (current === input.value) return { unchanged: true, verified: true };
    await this.fillValue(input, () => input.value, context);
    input.authorizeDispatch();
    const after = await this.evaluateField(context, wanted, selector, "READ");
    await this.confirmPage(wanted, context.frameId, context.loaderId);
    return { unchanged: false, verified: after === input.value };
  }

  private async evaluateField(
    context: { contextId: number },
    origin: string,
    selector: string,
    marker: "READ",
  ): Promise<string> {
    const value = await evaluate(
      this.transport,
      `(() => { const __agentsecret = "${marker}"; if (location.origin.toLowerCase() !== ${JSON.stringify(origin)}) return null; if (window !== window.top || document.querySelector("iframe,frame")) return null; const el = document.querySelector(${JSON.stringify(selector)}); if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) return null; if (el instanceof HTMLInputElement && ["button","checkbox","file","hidden","image","radio","reset","submit"].includes(el.type.toLowerCase())) return null; return typeof el.value === "string" ? el.value : null; })()`,
      context.contextId,
    );
    if (typeof value !== "string")
      throw new BrowserDriverError("browser_field_missing");
    return value;
  }

  async close(): Promise<void> {
    await this.transport.close();
  }
}
