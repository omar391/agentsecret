import assert from "node:assert/strict";
import { test } from "node:test";
import { createClient } from "@libsql/client/node";
import { createClient as createProductionClient } from "@tursodatabase/serverless/compat";
import { claimTransaction } from "../src/auth/transactions";
import {
  createRegistryDatabase,
  withRegistryDatabase,
} from "../src/registry/database";
import type { Env } from "../src/types";
import { applyMigrations } from "../scripts/migrate-turso.mjs";
import { readFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

test("production compat batch returns named rows for RETURNING and OAuth claims", async () => {
  const originalFetch = globalThis.fetch;
  const values: Record<string, string | number | null> = {
    state_hash: "state",
    provider: "github",
    cookie_hash: "cookie",
    code_verifier: "verifier",
    nonce: null,
    redirect_uri: "https://example.test/callback",
    link_account_id: null,
    created_at: 1,
    expires_at: 4102444800,
    consumed_at: 2,
  };
  let claimed = false;
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body));
    const steps = body.requests[0].batch.steps;
    const names = Object.keys(values);
    const typed = (value: string | number | null) =>
      value === null
        ? { type: "null" }
        : typeof value === "number"
          ? { type: "integer", value: String(value) }
          : { type: "text", value };
    const stepResults = steps.map((step: { stmt: { sql: string } }) => {
      if (!/RETURNING/i.test(step.stmt.sql))
        return { cols: [], rows: [], affected_row_count: 0 };
      const isClaim = /oauth_transactions/i.test(step.stmt.sql);
      const rows =
        isClaim && claimed ? [] : [names.map((name) => typed(values[name]))];
      if (isClaim) claimed = true;
      return {
        cols: names.map((name) => ({ name })),
        rows,
        affected_row_count: rows.length,
      };
    });
    return Response.json({
      baton: null,
      results: [
        {
          type: "ok",
          response: {
            type: "batch",
            result: {
              step_results: stepResults,
              step_errors: steps.map(() => null),
            },
          },
        },
        {
          type: "ok",
          response: { type: "get_autocommit", is_autocommit: true },
        },
      ],
    });
  };
  try {
    const client = createProductionClient({
      url: "https://synthetic.turso.io",
      authToken: "synthetic",
    });
    const db = createRegistryDatabase(client);
    const [result] = await db.batch([
      db.prepare("UPDATE example SET id=1 RETURNING *"),
    ]);
    assert.deepEqual(result.results[0], values);
    assert.equal(result.meta.changes, 1);
    const input = {
      provider: "github" as const,
      stateHash: "state",
      cookieHash: "cookie",
      sessionHash: null,
    };
    const claim = await claimTransaction(db, input);
    assert.equal(claim?.provider, "github");
    assert.equal(claim?.stateHash, "state");
    assert.equal(claim?.redirectUri, values.redirect_uri);
    assert.equal(await claimTransaction(db, input), null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Turso registry adapter preserves D1-style query results", async () => {
  const client = createClient({ url: "file::memory:", intMode: "number" });
  const db = createRegistryDatabase(client);
  try {
    await client.execute(
      "CREATE TABLE accounts (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
    );

    const insert = await db
      .prepare(
        "INSERT INTO accounts (id, name) VALUES (?, ?) RETURNING id, name",
      )
      .bind(1, "synthetic")
      .run<{ id: number; name: string }>();
    assert.equal(insert.meta.changes, 1);
    assert.deepEqual(insert.results, [{ id: 1, name: "synthetic" }]);

    const first = await db
      .prepare("SELECT name FROM accounts WHERE id = ?")
      .bind(1)
      .first<{ name: string }>();
    assert.deepEqual(first, { name: "synthetic" });

    const column = await db
      .prepare("SELECT name FROM accounts WHERE id = ?")
      .bind(1)
      .first<string>("name");
    assert.equal(column, "synthetic");

    const all = await db.prepare("SELECT id, name FROM accounts").all<{
      id: number;
      name: string;
    }>();
    assert.equal(all.success, true);
    assert.deepEqual(all.results, [{ id: 1, name: "synthetic" }]);
  } finally {
    client.close();
  }
});

test("Turso registry batches are atomic on statement failure", async () => {
  const client = createClient({ url: "file::memory:", intMode: "number" });
  const db = createRegistryDatabase(client);
  try {
    await client.execute(
      "CREATE TABLE accounts (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
    );

    await assert.rejects(
      db.batch([
        db
          .prepare("INSERT INTO accounts (id, name) VALUES (?, ?)")
          .bind(1, "first"),
        db.prepare("INSERT INTO missing_table (id) VALUES (?)").bind(2),
      ]),
    );

    const count = await db
      .prepare("SELECT COUNT(*) AS count FROM accounts")
      .first<{ count: number }>();
    assert.deepEqual(count, { count: 0 });
  } finally {
    client.close();
  }
});

test("Turso migration runner applies the checked-in schema once", async () => {
  const client = createClient({ url: "file::memory:", intMode: "number" });
  try {
    const migrations = resolve(process.cwd(), "migrations");
    const applied = await applyMigrations(client, migrations);
    assert.deepEqual(applied, [
      "0001_customer_registry",
      "0002_deletion_attempts",
      "0003_account_status_guard",
      "0004_oauth_transactions",
      "0005_oauth_link_sessions",
      "0006_account_onboarding",
    ]);

    const tables = await client.execute(
      "SELECT name FROM sqlite_master WHERE type = 'table'",
    );
    const names = new Set(tables.rows.map((row) => String(row.name)));
    for (const table of [
      "accounts",
      "identities",
      "oauth_transactions",
      "account_onboarding",
      "account_tombstones",
      "agentsecret_migrations",
    ])
      assert.ok(names.has(table), `expected migrated table ${table}`);

    await assert.rejects(
      client.execute({
        sql: "INSERT INTO accounts (id, status, created_at, updated_at) VALUES (?, ?, ?, ?)",
        args: ["acc_synthetic", "invalid", 1, 1],
      }),
      /account_status_invalid/,
    );
    assert.deepEqual(await applyMigrations(client, migrations), []);
  } finally {
    client.close();
  }
});

test("Turso migration runner refuses unknown applied migration records", async () => {
  const client = createClient({ url: "file::memory:", intMode: "number" });
  try {
    await client.execute(
      "CREATE TABLE agentsecret_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)",
    );
    await client.execute({
      sql: "INSERT INTO agentsecret_migrations (id, applied_at) VALUES (?, ?)",
      args: ["0999_unknown", 1],
    });

    await assert.rejects(
      applyMigrations(client, resolve(process.cwd(), "migrations")),
      /unknown_turso_migration_record/,
    );
    const tables = await client.execute(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'accounts'",
    );
    assert.equal(tables.rows.length, 0);
  } finally {
    client.close();
  }
});

test("Turso migration runner rolls back a failed migration", async () => {
  const client = createClient({ url: "file::memory:", intMode: "number" });
  const directory = await mkdtemp(
    join(tmpdir(), "agentsecret-turso-migration-"),
  );
  try {
    await writeFile(
      join(directory, "0001_partial_failure.sql"),
      "CREATE TABLE partial_migration (id INTEGER PRIMARY KEY); INSERT INTO missing_table VALUES (1);",
    );

    await assert.rejects(
      applyMigrations(client, directory),
      /turso_migration_failed:0001_partial_failure/,
    );
    const tables = await client.execute(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'partial_migration'",
    );
    assert.equal(tables.rows.length, 0);
  } finally {
    client.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("production environment adapts only a canonical Turso database URL", () => {
  const env = {
    REGISTRY_BACKEND: "turso",
    TURSO_DATABASE_URL: "turso://example-registry.turso.io",
    TURSO_AUTH_TOKEN: "synthetic-auth-token",
  } as unknown as Env;
  const adapted = withRegistryDatabase(env);
  const first = adapted.DB;
  const second = adapted.DB;
  assert.ok(first);
  assert.ok(second);
  assert.equal(first, second);
  assert.notEqual(withRegistryDatabase(env).DB, first);

  assert.throws(
    () =>
      withRegistryDatabase({
        TURSO_DATABASE_URL: "https://untrusted.example/database",
        TURSO_AUTH_TOKEN: "synthetic-auth-token",
        REGISTRY_BACKEND: "turso",
      } as unknown as Env),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "database_unavailable",
  );
});

test("explicit production Turso selection never falls back to a D1 binding", () => {
  const d1 = { prepare: () => ({}) };
  const env = {
    DB: d1,
    REGISTRY_BACKEND: "turso",
    TURSO_DATABASE_URL: "turso://example-registry.turso.io",
    TURSO_AUTH_TOKEN: "synthetic-auth-token",
  } as unknown as Env;

  const adapted = withRegistryDatabase(env);
  assert.notEqual(adapted.DB, d1);
  assert.equal(adapted.DB, adapted.DB);
  assert.notEqual(withRegistryDatabase(env).DB, adapted.DB);
});

test("Durable Object alarm reuses one registry adapter for both deletion cleanup paths", async () => {
  const source = await readFile(
    resolve(process.cwd(), "src/state/authority-kernel.ts"),
    "utf8",
  );
  const cleanupStart = source.indexOf("private async completeDeletion(");
  const cleanupEnd = source.indexOf(
    "\n  private async scheduleCleanup()",
    cleanupStart,
  );
  const cleanup = source.slice(cleanupStart, cleanupEnd);
  assert.match(
    cleanup,
    /private async completeDeletion\(accountId: string, db: RegistryDatabase\)/,
  );
  assert.doesNotMatch(cleanup, /requestDatabase\(/);

  const alarm = source.slice(source.indexOf("  async alarm()"));
  assert.match(alarm, /const db = this\.requestDatabase\(\);/);
  const fenced = alarm.match(
    /if \(outcome === "fenced"\) \{([\s\S]*?)\} else if \(outcome === "canceled" \|\| outcome === "absent"\)/,
  )?.[1];
  const committed = alarm.match(
    /\} else \{\n          \/\/ DO committed delete_account[\s\S]*?await this\.completeDeletion\(accountId, db\);/,
  )?.[0];
  assert.ok(fenced, "the fenced cleanup branch remains present");
  assert.match(fenced, /await this\.completeDeletion\(accountId, db\);/);
  assert.ok(committed, "the committed cleanup branch remains present");
});

test("explicit registry backend fails closed when its required binding is missing", () => {
  const d1 = { prepare: () => ({}) };
  assert.throws(
    () =>
      withRegistryDatabase({
        DB: d1,
        REGISTRY_BACKEND: "turso",
      } as unknown as Env),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "database_unavailable",
  );
  assert.throws(
    () =>
      withRegistryDatabase({
        REGISTRY_BACKEND: "d1",
      } as unknown as Env),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "database_unavailable",
  );
});
