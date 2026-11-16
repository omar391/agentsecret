import { spawn, type ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import type { BrowserTransport } from "./driver";

interface PendingCommand {
  resolve(value: unknown): void;
  reject(error: Error): void;
  timer: NodeJS.Timeout;
}

interface CdpMessage {
  id?: unknown;
  result?: unknown;
  error?: unknown;
}

/**
 * Browser-level Chrome DevTools Protocol over Chrome's private pipe transport.
 * It never opens or returns a TCP debugging endpoint.
 */
export class CdpPipeTransport {
  #nextId = 1;
  #pending = new Map<number, PendingCommand>();
  #buffer = Buffer.alloc(0);
  #closed = false;

  private constructor(
    private readonly child: ChildProcess,
    private readonly input: Writable,
    output: Readable,
  ) {
    output.on("data", (chunk: Buffer | string) => this.onData(chunk));
    output.on("error", () => this.failAll());
    child.once("error", () => this.failAll());
    child.once("exit", () => this.failAll());
  }

  static launch(options: {
    executable: string;
    profileDirectory: string;
    url: string;
    origin: string;
    signal?: AbortSignal;
    extraArgs?: string[];
  }): CdpPipeTransport {
    if (options.signal?.aborted) throw new Error("browser_cancelled");
    for (const arg of options.extraArgs || []) {
      if (
        typeof arg !== "string" ||
        arg.length > 1024 ||
        !/^--[a-z0-9-]+=[^\u0000-\u001f\u007f]+$/u.test(arg) ||
        !(
          arg.startsWith("--host-resolver-rules=") ||
          arg.startsWith("--ignore-certificate-errors-spki-list=")
        )
      )
        throw new Error("browser_target_invalid");
    }
    let target: URL;
    let origin: URL;
    try {
      target = new URL(options.url);
      origin = new URL(options.origin);
    } catch {
      throw new Error("browser_target_invalid");
    }
    const local =
      target.hostname === "localhost" ||
      target.hostname === "127.0.0.1" ||
      target.hostname === "[::1]";
    if (
      (target.protocol !== "https:" &&
        !(local && target.protocol === "http:")) ||
      target.username ||
      target.password ||
      target.search ||
      target.hash ||
      target.origin.toLowerCase() !== origin.origin.toLowerCase() ||
      origin.username ||
      origin.password ||
      origin.pathname !== "/" ||
      origin.search ||
      origin.hash
    )
      throw new Error("browser_target_invalid");
    const child = spawn(
      options.executable,
      [
        "--headless=new",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-background-networking",
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-debugging-pipe",
        `--user-data-dir=${options.profileDirectory}`,
        ...(options.extraArgs || []),
        options.url,
      ],
      {
        stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"],
        windowsHide: true,
      },
    );
    const input = child.stdio[3];
    const output = child.stdio[4];
    if (
      !input ||
      !output ||
      typeof (input as Writable).write !== "function" ||
      typeof (output as Readable).on !== "function"
    ) {
      child.kill("SIGKILL");
      throw new Error("browser_pipe_unavailable");
    }
    return new CdpPipeTransport(child, input as Writable, output as Readable);
  }

  private onData(chunk: Buffer | string): void {
    if (this.#closed) return;
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    this.#buffer = Buffer.concat([this.#buffer, bytes]);
    if (this.#buffer.length > 8 * 1024 * 1024) {
      this.failAll();
      this.child.kill("SIGKILL");
      return;
    }
    while (true) {
      const delimiter = this.#buffer.indexOf(0);
      if (delimiter < 0) return;
      const frame = this.#buffer.subarray(0, delimiter);
      this.#buffer = this.#buffer.subarray(delimiter + 1);
      if (frame.length === 0) continue;
      let message: CdpMessage;
      try {
        message = JSON.parse(frame.toString("utf8")) as CdpMessage;
      } catch {
        this.failAll();
        this.child.kill("SIGKILL");
        return;
      }
      if (!Number.isSafeInteger(message.id)) continue;
      const pending = this.#pending.get(message.id as number);
      if (!pending) continue;
      this.#pending.delete(message.id as number);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error("cdp_command_failed"));
      else pending.resolve(message.result);
    }
  }

  private failAll(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("cdp_unavailable"));
    }
    this.#pending.clear();
  }

  send(
    method: string,
    params: Record<string, unknown>,
    sessionId?: string,
  ): Promise<unknown> {
    if (this.#closed) return Promise.reject(new Error("cdp_unavailable"));
    if (!/^[A-Za-z][A-Za-z0-9.]{0,127}$/.test(method))
      return Promise.reject(new Error("cdp_command_invalid"));
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error("cdp_timeout"));
      }, 5_000);
      this.#pending.set(id, { resolve, reject, timer });
      try {
        this.input.write(
          Buffer.concat([
            Buffer.from(
              JSON.stringify({
                id,
                method,
                params,
                ...(sessionId ? { sessionId } : {}),
              }),
              "utf8",
            ),
            Buffer.from([0]),
          ]),
        );
      } catch {
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(new Error("cdp_unavailable"));
      }
    });
  }

  async attachPage(): Promise<BrowserTransport> {
    const response = (await this.send("Target.getTargets", {})) as {
      targetInfos?: Array<{
        targetId?: unknown;
        type?: unknown;
        url?: unknown;
      }>;
    };
    const pages = (response.targetInfos || []).filter(
      (target) => target.type === "page" && typeof target.targetId === "string",
    );
    if (pages.length !== 1) throw new Error("browser_target_invalid");
    const attached = (await this.send("Target.attachToTarget", {
      targetId: pages[0]!.targetId,
      flatten: true,
    })) as { sessionId?: unknown };
    if (typeof attached.sessionId !== "string")
      throw new Error("browser_target_invalid");
    return new CdpPageSession(this, attached.sessionId);
  }

  async close(): Promise<void> {
    if (!this.#closed) {
      try {
        await this.send("Browser.close", {});
      } catch {
        // A browser that already exited has no remaining protected state to use.
      }
    }
    if (this.child.exitCode === null && this.child.signalCode === null) {
      this.child.kill("SIGTERM");
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          if (this.child.exitCode === null) this.child.kill("SIGKILL");
          resolve();
        }, 2_000);
        this.child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    this.failAll();
  }
}

class CdpPageSession implements BrowserTransport {
  constructor(
    private readonly browser: CdpPipeTransport,
    private readonly sessionId: string,
  ) {}

  send(method: string, params: Record<string, unknown>): Promise<unknown> {
    return this.browser.send(method, params, this.sessionId);
  }

  async close(): Promise<void> {
    try {
      await this.browser.send("Target.detachFromTarget", {
        sessionId: this.sessionId,
      });
    } catch {
      // Closing the parent pipe also terminates the attached target.
    }
  }
}
