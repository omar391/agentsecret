import { createHash } from "node:crypto";
import { mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { AuthorityKernel, type Command } from "../state/authority-kernel";
import type { Env } from "../types";
import { SqliteAuthorityStorage } from "./authority-storage";

type TenantRuntime = {
  kernel: AuthorityKernel;
  storage: SqliteAuthorityStorage;
  db: DatabaseSync;
};

/**
 * The in-process account authority for a self-hosted Node server.
 *
 * This is the Node counterpart of the Cloudflare `SECURITY` Durable Object
 * namespace. It keeps one `AuthorityKernel` per tenant, each backed by its
 * own synchronous SQLite file under `<dataDir>/authority/`, so the same
 * business rules, records schema and deletion/alarm recovery run unchanged.
 * Scheduled recovery is durable: `setAlarm` persists the instant and a host
 * timer fires `kernel.alarm()` when it comes due, resuming any persisted
 * alarm after a restart.
 */
export class NodeAuthorityHost {
  private readonly dir: string;
  private readonly env: Env;
  private readonly runtimes = new Map<string, TenantRuntime>();
  private timer: NodeJS.Timeout | null = null;
  private closed = false;

  constructor(options: { dataDir: string; env: Env }) {
    this.dir = join(options.dataDir, "authority");
    this.env = options.env;
    mkdirSync(this.dir, { recursive: true });
  }

  /** A Durable-Object-namespace-shaped dispatcher for `env.SECURITY`. */
  namespace(): {
    getByName(tenant: string): { dispatch(command: unknown): Promise<unknown> };
  } {
    return {
      getByName: (tenant: string) => ({
        dispatch: (command: unknown) => this.dispatch(tenant, command),
      }),
    };
  }

  async dispatch(tenant: string, command: unknown): Promise<unknown> {
    const result = await this.runtime(tenant).kernel.dispatch(
      command as Command,
    );
    this.reschedule();
    return result;
  }

  private fileFor(tenant: string): string {
    // Tenant ids are already constrained to [A-Za-z0-9_-] by the routing gate;
    // fall back to a stable hash for any unexpected value so a tenant string
    // can never escape the authority directory.
    const safe = /^[A-Za-z0-9_-]{1,80}$/.test(tenant)
      ? tenant
      : "t-" + createHash("sha256").update(tenant).digest("hex").slice(0, 24);
    return join(this.dir, safe + ".db");
  }

  private open(tenant: string, db: DatabaseSync): TenantRuntime {
    db.exec(
      "CREATE TABLE IF NOT EXISTS authority_meta (id INTEGER PRIMARY KEY CHECK (id = 1), tenant TEXT NOT NULL)",
    );
    db.prepare(
      "INSERT OR REPLACE INTO authority_meta (id, tenant) VALUES (1, ?)",
    ).run(tenant);
    const storage = new SqliteAuthorityStorage(db, () => this.reschedule());
    const kernel = new AuthorityKernel({
      storage,
      env: this.env,
      background: (promise) => {
        promise.catch(() => {});
      },
      instanceName: tenant,
    });
    const runtime: TenantRuntime = { kernel, storage, db };
    this.runtimes.set(tenant, runtime);
    return runtime;
  }

  private runtime(tenant: string): TenantRuntime {
    const existing = this.runtimes.get(tenant);
    if (existing) return existing;
    return this.open(tenant, new DatabaseSync(this.fileFor(tenant)));
  }

  /**
   * Resume durable scheduled recovery after a restart: open every tenant
   * database that still holds an alarm and arm the host timer for the
   * earliest one. Databases without a pending alarm are left unopened until
   * their tenant is next dispatched.
   */
  resume(): void {
    for (const file of readdirSync(this.dir)) {
      if (!file.endsWith(".db")) continue;
      const path = join(this.dir, file);
      let db: DatabaseSync;
      try {
        db = new DatabaseSync(path);
      } catch {
        continue;
      }
      try {
        const meta = db
          .prepare("SELECT tenant FROM authority_meta WHERE id = 1")
          .get() as { tenant: string } | undefined;
        const alarm = db
          .prepare("SELECT alarm_at FROM authority_alarm WHERE id = 1")
          .get() as { alarm_at: number } | undefined;
        if (!meta || !alarm) {
          db.close();
          continue;
        }
        // Reuse the already-open handle rather than opening a second one.
        const runtime = this.open(meta.tenant, db);
        void runtime;
      } catch {
        try {
          db.close();
        } catch {
          // Ignore close failures on an already-broken handle.
        }
      }
    }
    this.reschedule();
  }

  private nextAlarmAt(): number | null {
    let earliest: number | null = null;
    for (const runtime of this.runtimes.values()) {
      const at = runtime.storage.alarmAt();
      if (at !== null && (earliest === null || at < earliest)) earliest = at;
    }
    return earliest;
  }

  private reschedule(): void {
    if (this.closed) return;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const next = this.nextAlarmAt();
    if (next === null) return;
    const delay = Math.max(0, next - Date.now());
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.fireDue();
    }, delay);
    this.timer.unref?.();
  }

  private async fireDue(): Promise<void> {
    if (this.closed) return;
    const now = Date.now();
    for (const runtime of this.runtimes.values()) {
      const at = runtime.storage.alarmAt();
      if (at !== null && at <= now) {
        try {
          await runtime.kernel.alarm();
          if (runtime.storage.alarmAt() === at)
            await runtime.storage.deleteAlarm();
        } catch {
          // A failed alarm re-arms itself inside the kernel; the next
          // reschedule picks up whatever instant it persisted.
        }
      }
    }
    this.reschedule();
  }

  close(): void {
    this.closed = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    for (const runtime of this.runtimes.values()) {
      try {
        runtime.db.close();
      } catch {
        // Best-effort shutdown.
      }
    }
    this.runtimes.clear();
  }
}
