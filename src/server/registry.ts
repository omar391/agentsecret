import { readdirSync, readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import type {
  RegistryDatabase,
  RegistryPreparedStatement,
  RegistryResult,
} from "../registry/database";

/**
 * The D1-compatible registry database over a local synchronous SQLite file.
 *
 * The account/identity registry is the one piece of state the Cloudflare
 * deployment keeps in Turso/D1 rather than in a Durable Object. A self-hosted
 * Node server keeps it in one local SQLite file with the same schema (the
 * repository migrations), so the registry rules in `src/registry` run
 * unchanged. Statements are executed synchronously and wrapped in the async
 * RegistryDatabase surface the application already uses.
 */
class SqliteRegistryStatement implements RegistryPreparedStatement {
  constructor(
    private readonly db: DatabaseSync,
    readonly sql: string,
    private readonly args: unknown[] = [],
    private readonly serialize: <T>(work: () => T) => Promise<T> = (work) =>
      Promise.resolve(work()),
  ) {}

  bind(...values: unknown[]): SqliteRegistryStatement {
    return new SqliteRegistryStatement(
      this.db,
      this.sql,
      values,
      this.serialize,
    );
  }

  private rows(): Record<string, unknown>[] {
    const statement = this.db.prepare(this.sql);
    return statement.all(...(this.args as never[])) as Record<
      string,
      unknown
    >[];
  }

  runSync<T = Record<string, unknown>>(): RegistryResult<T> {
    if (/\bRETURNING\b/i.test(this.sql)) {
      const rows = this.rows() as T[];
      return { success: true, results: rows, meta: { changes: rows.length } };
    }
    return { success: true, results: [], meta: { changes: this.changes() } };
  }

  allSync<T = Record<string, unknown>>(): RegistryResult<T> {
    const rows = this.rows() as T[];
    return {
      success: true,
      results: rows,
      meta: { changes: /\bRETURNING\b/i.test(this.sql) ? rows.length : 0 },
    };
  }

  private changes(): number {
    const statement = this.db.prepare(this.sql);
    const outcome = statement.run(...(this.args as never[]));
    return Number(outcome.changes);
  }

  async first<T = Record<string, unknown>>(
    columnName?: string,
  ): Promise<T | null> {
    const row = await this.serialize(() => this.rows()[0]);
    if (!row) return null;
    return (columnName === undefined ? row : row[columnName]) as T;
  }

  async all<T = Record<string, unknown>>(): Promise<RegistryResult<T>> {
    const rows = (await this.serialize(() => this.rows())) as T[];
    return {
      success: true,
      results: rows,
      meta: { changes: /\bRETURNING\b/i.test(this.sql) ? rows.length : 0 },
    };
  }

  async run<T = Record<string, unknown>>(): Promise<RegistryResult<T>> {
    return this.serialize(() => this.runSync<T>());
  }
}

export class SqliteRegistryDatabase implements RegistryDatabase {
  private tail: Promise<void> = Promise.resolve();

  constructor(private readonly db: DatabaseSync) {}

  private async exclusive<T>(work: () => T): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => (release = resolve));
    await previous;
    try {
      return work();
    } finally {
      release();
    }
  }

  prepare(query: string): RegistryPreparedStatement {
    return new SqliteRegistryStatement(this.db, query, [], (work) =>
      this.exclusive(work),
    );
  }

  async batch<T = unknown>(
    statements: RegistryPreparedStatement[],
  ): Promise<RegistryResult<T>[]> {
    if (statements.length === 0) return [];
    if (
      statements.some(
        (statement) => !(statement instanceof SqliteRegistryStatement),
      )
    )
      throw new Error("registry_batch_statement_mismatch");
    const input = statements as SqliteRegistryStatement[];
    return this.exclusive(() => {
      this.db.exec("BEGIN IMMEDIATE");
      try {
        const results = input.map((statement) =>
          /\bRETURNING\b/i.test(statement.sql)
            ? statement.allSync<T>()
            : statement.runSync<T>(),
        );
        this.db.exec("COMMIT");
        return results;
      } catch (error) {
        try {
          this.db.exec("ROLLBACK");
        } catch {
          // Preserve the original failure.
        }
        throw error;
      }
    });
  }
}

/**
 * Apply the repository migrations to a registry database, once each, in
 * filename order. Applied names are recorded so a restart never re-runs a
 * migration (the status-guard triggers in 0003 are not idempotent).
 */
export function applyRegistryMigrations(
  db: DatabaseSync,
  migrationsDir: string,
): void {
  db.exec(
    "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)",
  );
  const applied = new Set(
    (
      db.prepare("SELECT name FROM _migrations").all() as { name: string }[]
    ).map((row) => row.name),
  );
  const files = readdirSync(migrationsDir)
    .filter((name) => name.endsWith(".sql"))
    .sort();
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = readFileSync(migrationsDir + "/" + file, "utf8");
    db.exec(sql);
    db.prepare("INSERT INTO _migrations (name, applied_at) VALUES (?, ?)").run(
      file,
      Date.now(),
    );
  }
}
