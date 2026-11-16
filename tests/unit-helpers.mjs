import { build } from "esbuild";
import { mkdir, readFile, readdir } from "node:fs/promises";
import { randomBytes, webcrypto } from "node:crypto";
import { exportJWK, SignJWT } from "jose";
const root = new URL("../", import.meta.url).pathname;
export const origin = "http://localhost";
await mkdir(root + "tmp/tests", { recursive: true });
// The unit harness bundles only platform-neutral modules (no Worker entry, no Durable
// Object, no Miniflare), so it is safe to run in the public Node/SQLite snapshot. The
// Worker fixture that needs the private Cloudflare harness lives in helpers.mjs.
await build({
  entryPoints: [root + "tests/unit-harness.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  outfile: root + "tmp/tests/unit.mjs",
  plugins: [
    {
      name: "synthetic-provider-transport",
      setup(build) {
        build.onResolve({ filter: /pinned-fetch/ }, ({ path, importer }) =>
          importer.endsWith("src/bitwarden/client.ts")
            ? { path: root + "tests/provider-pinned-fetch-fixture.ts" }
            : undefined,
        );
      },
    },
  ],
});
export const unit = await import(root + "tmp/tests/unit.mjs");

/**
 * The deployed migrations are the single schema source: the harness never carries its own copy
 * of the DDL, it applies exactly the files under `migrations/` that production applies.
 */
export function splitSqlStatements(sql) {
  const statements = [];
  let current = "";
  let inBlock = false;
  for (const line of sql.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("--") || trimmed === "") continue;
    current += line + "\n";
    if (/\bBEGIN\b/i.test(trimmed)) inBlock = true;
    if (inBlock && /\bEND\s*;?$/i.test(trimmed)) inBlock = false;
    if (!inBlock && trimmed.endsWith(";")) {
      statements.push(current.trim().replace(/;$/, ""));
      current = "";
    }
  }
  if (current.trim()) statements.push(current.trim().replace(/;$/, ""));
  return statements;
}

export const migrationsDirectory = root + "migrations";

export async function migrationFiles(directory = migrationsDirectory) {
  const files = (await readdir(directory))
    .filter((f) => f.endsWith(".sql"))
    .sort();
  return Promise.all(
    files.map(async (name) => ({
      name,
      sql: await readFile(directory + "/" + name, "utf8"),
    })),
  );
}

const migrationStatements = (await migrationFiles()).flatMap((file) =>
  splitSqlStatements(file.sql),
);

export { migrationStatements };

export async function applyMigrations(db, statements = migrationStatements) {
  if (statements.length > 0) {
    await db.batch(statements.map((statement) => db.prepare(statement)));
  }
}
export function digest(s) {
  return webcrypto.subtle
    .digest("SHA-256", Buffer.from(s))
    .then((value) => Buffer.from(value).toString("base64url"));
}
export function random() {
  return randomBytes(32).toString("base64url");
}
export async function keys() {
  return webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}
export async function proof(pair, method, url, token, text, extra = {}) {
  const u = new URL(url);
  const payload = { htm: method, htu: u.origin + u.pathname, ...extra };
  if (token) payload.ath = await digest(token);
  if (text !== undefined) payload.rqh = await digest(text);
  return new SignJWT(payload)
    .setProtectedHeader({
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: await exportJWK(pair.publicKey),
    })
    .setIssuedAt(extra.iat ?? Math.floor(Date.now() / 1000))
    .setJti(extra.jti || random())
    .sign(pair.privateKey);
}
