import {
  createClient,
  type Client,
  type InArgs,
  type ResultSet,
} from "@tursodatabase/serverless/compat";
import type { Env } from "../types";
import { HttpError } from "../security/primitives";

export interface RegistryResult<T = unknown> {
  success: true;
  results: T[];
  meta: { changes: number };
}

export interface RegistryPreparedStatement {
  bind(...values: unknown[]): RegistryPreparedStatement;
  first<T = Record<string, unknown>>(columnName?: string): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<RegistryResult<T>>;
  run<T = Record<string, unknown>>(): Promise<RegistryResult<T>>;
}

export interface RegistryDatabase {
  prepare(query: string): RegistryPreparedStatement;
  batch<T = unknown>(
    statements: RegistryPreparedStatement[],
  ): Promise<RegistryResult<T>[]>;
}

function objectRows(result: ResultSet): Record<string, unknown>[] {
  return result.rows.map((row) => {
    const value: Record<string, unknown> = {};
    for (let index = 0; index < result.columns.length; index += 1) {
      const column = result.columns[index];
      // The production compat client's batch() returns named objects, while
      // execute() and libSQL clients can return array-like rows.
      value[column] = Object.prototype.hasOwnProperty.call(row, column)
        ? (row as unknown as Record<string, unknown>)[column]
        : row[index];
    }
    return value;
  });
}

function result<T>(value: ResultSet, sql: string): RegistryResult<T> {
  return {
    success: true,
    results: objectRows(value) as T[],
    meta: {
      changes:
        value.rowsAffected ||
        (/\bRETURNING\b/i.test(sql) ? value.rows.length : 0),
    },
  };
}

class TursoPreparedStatement implements RegistryPreparedStatement {
  constructor(
    readonly client: Client,
    readonly sql: string,
    readonly args: unknown[] = [],
  ) {}

  bind(...values: unknown[]): TursoPreparedStatement {
    return new TursoPreparedStatement(this.client, this.sql, values);
  }

  async first<T = Record<string, unknown>>(
    columnName?: string,
  ): Promise<T | null> {
    const response = await this.client.execute({
      sql: this.sql,
      args: this.args as InArgs,
    });
    const row = objectRows(response)[0];
    if (!row) return null;
    return (columnName === undefined ? row : row[columnName]) as T;
  }

  async all<T = Record<string, unknown>>(): Promise<RegistryResult<T>> {
    return result<T>(
      await this.client.execute({ sql: this.sql, args: this.args as InArgs }),
      this.sql,
    );
  }

  async run<T = Record<string, unknown>>(): Promise<RegistryResult<T>> {
    return result<T>(
      await this.client.execute({ sql: this.sql, args: this.args as InArgs }),
      this.sql,
    );
  }
}

class TursoRegistryDatabase implements RegistryDatabase {
  constructor(private readonly client: Client) {}

  prepare(query: string): TursoPreparedStatement {
    return new TursoPreparedStatement(this.client, query);
  }

  async batch<T = unknown>(
    statements: RegistryPreparedStatement[],
  ): Promise<RegistryResult<T>[]> {
    if (statements.length === 0) return [];
    if (
      statements.some(
        (statement) =>
          !(statement instanceof TursoPreparedStatement) ||
          statement.client !== this.client,
      )
    )
      throw new Error("registry_batch_statement_mismatch");

    const input = statements as TursoPreparedStatement[];
    const results = await this.client.batch(
      input.map(({ sql, args }) => ({ sql, args: args as InArgs })),
      "write",
    );
    return results.map((entry, index) => result<T>(entry, input[index].sql));
  }
}

export function createRegistryDatabase(client: Client): RegistryDatabase {
  return new TursoRegistryDatabase(client);
}

function requireCanonicalTursoUrl(value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new HttpError(503, "database_unavailable");
  }
  if (
    parsed.protocol !== "turso:" ||
    !parsed.hostname.endsWith(".turso.io") ||
    parsed.username ||
    parsed.password ||
    (parsed.pathname !== "" && parsed.pathname !== "/") ||
    parsed.search ||
    parsed.hash
  )
    throw new HttpError(503, "database_unavailable");
}

/**
 * Use the local D1 binding in development and tests. Production has no D1 binding;
 * its registry is Turso over HTTPS through the Cloudflare Workers web client.
 *
 * The Turso client owns request-scoped state, including an async execution lock. Caching
 * one client on a reused Worker environment let a continuation from a completed request
 * run inside a later request; Cloudflare cancels those continuations and the later request
 * can hang. Each adapter is therefore scoped to one `withRegistryDatabase` call, while
 * repeated `DB` reads from that adapted environment return the same client.
 */
export function withRegistryDatabase(env: Env): Env {
  const backend = env.REGISTRY_BACKEND;
  if (backend === "d1") {
    if (!env.DB) throw new HttpError(503, "database_unavailable");
    return env;
  }
  if (backend !== "turso") {
    if (backend !== undefined) throw new HttpError(503, "database_unavailable");
    // Test and legacy local environments can still expose their explicit D1
    // binding. Remote Turso access must always be selected by configuration.
    if (env.DB) return env;
    throw new HttpError(503, "database_unavailable");
  }
  if (!env.TURSO_DATABASE_URL || !env.TURSO_AUTH_TOKEN)
    throw new HttpError(503, "database_unavailable");
  requireCanonicalTursoUrl(env.TURSO_DATABASE_URL);

  const database = createRegistryDatabase(
    createClient({
      url: env.TURSO_DATABASE_URL,
      authToken: env.TURSO_AUTH_TOKEN,
    }),
  );
  return new Proxy(env, {
    get(target, property) {
      if (property === "DB") return database;
      return Reflect.get(target, property, target);
    },
  });
}
