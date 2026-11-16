import { createClient } from "@tursodatabase/serverless/compat";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const migrationsDirectory = fileURLToPath(
  new URL("../migrations/", import.meta.url),
);

function validDatabaseUrl(value) {
  try {
    const url = new URL(value);
    return (
      url.protocol === "turso:" &&
      url.hostname.endsWith(".turso.io") &&
      !url.username &&
      !url.password &&
      (url.pathname === "" || url.pathname === "/") &&
      !url.search &&
      !url.hash
    );
  } catch {
    return false;
  }
}

export async function applyMigrations(client, directory = migrationsDirectory) {
  const files = (await readdir(directory))
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/.test(name))
    .sort();
  const known = new Set(files.map((name) => name.slice(0, -4)));

  await client.execute(
    "CREATE TABLE IF NOT EXISTS agentsecret_migrations (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)",
  );
  const existing = await client.execute(
    "SELECT id FROM agentsecret_migrations",
  );
  const applied = new Set(existing.rows.map((row) => String(row.id)));
  for (const id of applied) {
    if (!known.has(id)) throw new Error("unknown_turso_migration_record");
  }

  const newlyApplied = [];
  for (const file of files) {
    const id = file.slice(0, -4);
    if (applied.has(id)) continue;
    const sql = await readFile(join(directory, file), "utf8");
    const transaction = await client.transaction("write");
    try {
      const alreadyApplied = await transaction.execute({
        sql: "SELECT 1 AS present FROM agentsecret_migrations WHERE id = ?",
        args: [id],
      });
      if (alreadyApplied.rows.length !== 0) {
        await transaction.rollback();
        applied.add(id);
        continue;
      }
      await transaction.executeMultiple(sql);
      await transaction.execute({
        sql: "INSERT INTO agentsecret_migrations (id, applied_at) VALUES (?, ?)",
        args: [id, Math.floor(Date.now() / 1000)],
      });
      await transaction.commit();
      applied.add(id);
      newlyApplied.push(id);
    } catch {
      await transaction.rollback().catch(() => {});
      throw new Error(`turso_migration_failed:${id}`);
    }
  }
  return newlyApplied;
}

async function main() {
  const url = process.env.TURSO_DATABASE_URL;
  const authToken = process.env.TURSO_AUTH_TOKEN;
  if (!url || !authToken || !validDatabaseUrl(url))
    throw new Error("turso_migration_configuration_missing");

  const client = createClient({ url, authToken });
  try {
    const applied = await applyMigrations(client);
    console.log(
      applied.length === 0
        ? "Turso migrations are already current."
        : `Applied Turso migrations: ${applied.join(", ")}`,
    );
  } finally {
    client.close();
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    console.error(
      error instanceof Error ? error.message : "turso_migration_failed",
    );
    process.exitCode = 1;
  });
}
