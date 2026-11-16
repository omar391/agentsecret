import type { BrowserTransport } from "./driver";

export class CdpTransport implements BrowserTransport {
  #nextId = 1;
  #pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (error: Error) => void }
  >();

  private constructor(private readonly socket: WebSocket) {
    socket.addEventListener("message", (event) => {
      let message: {
        id?: number;
        result?: unknown;
        error?: { message?: string };
      };
      try {
        message = JSON.parse(String(event.data));
      } catch {
        return;
      }
      if (typeof message.id !== "number") return;
      const pending = this.#pending.get(message.id);
      if (!pending) return;
      this.#pending.delete(message.id);
      if (message.error) pending.reject(new Error("cdp_error"));
      else pending.resolve(message.result);
    });
  }

  static async connect(port: number, timeoutMs = 5_000): Promise<CdpTransport> {
    if (!Number.isInteger(port) || port < 1 || port > 65_535)
      throw new Error("cdp_port_invalid");
    const deadline = Date.now() + timeoutMs;
    let target: { webSocketDebuggerUrl?: string; type?: string } | undefined;
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/json/list`);
        const targets = (await response.json()) as Array<{
          webSocketDebuggerUrl?: string;
          type?: string;
        }>;
        target = targets.find(
          (entry) => entry.type === "page" && entry.webSocketDebuggerUrl,
        );
        if (target) break;
      } catch {
        // Chrome has not opened its endpoint yet.
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (!target?.webSocketDebuggerUrl) throw new Error("cdp_unavailable");
    const socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("cdp_unavailable")),
        timeoutMs,
      );
      socket.addEventListener("open", () => {
        clearTimeout(timer);
        resolve();
      });
      socket.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error("cdp_unavailable"));
      });
    });
    return new CdpTransport(socket);
  }

  send(method: string, params: Record<string, unknown>): Promise<unknown> {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error("cdp_timeout"));
      }, 5_000);
      this.#pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      try {
        this.socket.send(JSON.stringify({ id, method, params }));
      } catch {
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(new Error("cdp_unavailable"));
      }
    });
  }

  close(): void {
    this.socket.close();
  }
}
