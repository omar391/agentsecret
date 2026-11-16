import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function read(path) {
  return readFile(join(root, path), "utf8");
}

test("license files and package notices exist and state the chosen licenses", async () => {
  const agpl = await read("LICENSE-AGPL.md");
  assert.match(agpl, /GNU AFFERO GENERAL PUBLIC LICENSE/);
  assert.match(agpl, /Version 3, 19 November 2007/);
  assert.match(await read("protocol/LICENSE-MIT.md"), /MIT License/);
  const notice = await read("NOTICE.md");
  assert.match(notice, /AGPL-3\.0-only/);
  assert.match(notice, /MIT/);
  assert.match(notice, /jose/);
  assert.match(notice, /tursodatabase/);
  const packageManifest = JSON.parse(await read("package.json"));
  assert.notEqual(packageManifest.main, "src/index.ts");
  assert.ok(packageManifest.files.includes("dist/THIRD-PARTY-NOTICES.txt"));
  assert.equal(packageManifest.files.includes("dist/server/"), false);
  const bundledNotices = await read("dist/THIRD-PARTY-NOTICES.txt");
  assert.match(bundledNotices, /@1password\/sdk@0\.5\.0/);
  assert.match(bundledNotices, /@1password\/sdk-core@0\.5\.0/);
  assert.match(bundledNotices, /Copyright \(c\) 2024 1Password/);
  const pkg = JSON.parse(await read("package.json"));
  assert.equal(pkg.license, "MIT");
  const web = JSON.parse(await read("web/package.json"));
  assert.equal(web.license, "AGPL-3.0-only");
  const cargo = await read("native/agentsecret-supervisor/Cargo.toml");
  assert.match(cargo, /license = "MIT"/);
  assert.match(await read("docs/source-access.md"), /Corresponding Source/);
  assert.match(await read("package.json"), /build:source-access/);
  const source = await readFile(join(root, "web/dist/source.tar.gz"));
  const digest = createHash("sha256").update(source).digest("hex");
  const manifest = JSON.parse(await read("web/dist/source-revision.json"));
  assert.equal(manifest.sha256, digest);
  assert.match(await read("web/dist/source.tar.gz.sha256"), new RegExp(digest));
  const paths = execFileSync(
    "tar",
    ["-tzf", join(root, "web/dist/source.tar.gz")],
    {
      encoding: "utf8",
    },
  );
  assert.match(paths, /package-lock\.json/);
  assert.match(paths, /migrations\//);
  assert.match(paths, /LICENSE-AGPL\.md/);
  assert.doesNotMatch(
    paths,
    /docs\/evidence|key-custody-and-rotation|dev-learnings/,
  );
  assert.match(await read("COMMERCIAL-LICENSE.md"), /commercial license/i);
});

test("source archive excludes default and configured runtime storage", async () => {
  const suffix = process.pid + "-" + Date.now();
  const defaultFixture = "data/registry-review-" + suffix + ".db";
  const configuredDir = ".runtime-review-" + suffix;
  const configuredFixture = configuredDir + "/authority/customer.db";
  await mkdir(join(root, "data"), { recursive: true });
  await mkdir(join(root, configuredDir, "authority"), { recursive: true });
  await writeFile(join(root, defaultFixture), "synthetic customer record");
  await writeFile(join(root, configuredFixture), "synthetic authority state");
  try {
    execFileSync(process.execPath, ["web/scripts/build-source-archive.mjs"], {
      cwd: root,
      env: { ...process.env, AGENTSECRET_DATA_DIR: configuredDir },
      stdio: "pipe",
    });
    const paths = execFileSync(
      "tar",
      ["-tzf", join(root, "web/public/source.tar.gz")],
      { encoding: "utf8" },
    );
    assert.doesNotMatch(paths, /data\/registry-review-/);
    assert.doesNotMatch(paths, /\.runtime-review-/);
  } finally {
    await rm(join(root, defaultFixture), { force: true });
    await rm(join(root, configuredDir), { recursive: true, force: true });
  }
});

test("MIT protocol modules never import AGPL server modules by path", async () => {
  const forbidden = [
    /(^|\/)src\/(?:state|registry|auth|mcp|vaults|bitwarden|broker|server|core)(?:\/|$)/,
    /(^|\/)src\/index(?:\.ts)?$/,
  ];
  const sharedHelpers = new Set(["src/security/primitives.ts"]);
  async function* walk(dir) {
    for (const item of await readdir(dir, { withFileTypes: true })) {
      if (item.name === "node_modules") continue;
      const full = join(dir, item.name);
      if (item.isDirectory()) yield* walk(full);
      else if (/\.(ts|mjs|js)$/.test(item.name)) yield full;
    }
  }
  const files = [];
  for await (const file of walk(join(root, "protocol"))) files.push(file);
  assert.ok(files.length >= 4, "protocol package files must be discovered");
  const modules = new Map();
  for (const file of files) modules.set(file, await readFile(file, "utf8"));
  function imports(source) {
    const found = [];
    const pattern =
      /(?:\b(?:import|export)\s+(?:[^'";]*?\s+from\s*)?|\bimport\s*)["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
    for (const match of source.matchAll(pattern))
      found.push(match[1] || match[2]);
    return found;
  }
  function resolveModule(from, specifier) {
    const base = resolve(dirname(from), specifier);
    const candidates = extname(base)
      ? [base]
      : [
          base,
          ...[".ts", ".js", ".mjs"].map((extension) => base + extension),
          ...["index.ts", "index.js"].map((name) => join(base, name)),
        ];
    return candidates.find(
      (candidate) => modules.has(candidate) || existsSync(candidate),
    );
  }
  function isForbidden(path) {
    const rel = relative(root, path).replaceAll("\\", "/");
    if (rel.startsWith("src/security/") && !sharedHelpers.has(rel)) return true;
    return forbidden.some((pattern) => pattern.test(rel));
  }
  function assertSafeGraph(entry, seen = new Set()) {
    if (seen.has(entry)) return;
    seen.add(entry);
    const source = modules.has(entry)
      ? modules.get(entry)
      : readFileSync(entry, "utf8");
    for (const specifier of imports(source)) {
      if (!specifier.startsWith(".")) continue;
      const target = resolveModule(entry, specifier);
      if (!target) continue;
      assert.equal(
        isForbidden(target),
        false,
        relative(root, entry) + " reaches a server module: " + specifier,
      );
      assertSafeGraph(target, seen);
    }
  }
  for (const file of files) {
    assertSafeGraph(file);
  }
  const entry = files.find((file) => file.endsWith("/executor-id.ts"));
  assert.ok(entry, "executor-id protocol module must be discovered");
  const original = modules.get(entry);
  const primitive = join(root, "src/security/primitives.ts");
  modules.set(entry, "import '../src/security/primitives.ts';");
  modules.set(primitive, "import '../state/authority-kernel.ts';");
  assert.throws(() => assertSafeGraph(entry), /reaches a server module/);
  modules.set(entry, original);
  modules.delete(primitive);
  assert.equal(isForbidden(primitive), false);
  assert.equal(isForbidden(join(root, "src/security/auth.ts")), true);
});

test("hosted CLI bundles carry their dependency notices", async () => {
  const notices = await read("dist/THIRD-PARTY-NOTICES.txt");
  for (const path of [
    "dist/cli.mjs",
    "web/public/cli.mjs",
    "web/dist/cli.mjs",
  ]) {
    const artifact = await read(path);
    const embeddedNotices = artifact.match(
      /(?:^|\n)const THIRD_PARTY_NOTICES = ("(?:\\.|[^"\\])*");(?:\r?\n|$)/,
    );
    assert.ok(embeddedNotices, path + " must embed dependency notices");
    assert.equal(JSON.parse(embeddedNotices[1]), notices);
  }
});

test("the built CLI bundle contains no AGPL server implementation", async () => {
  const bundle = await readFile(join(root, "dist/cli.mjs"));
  const probes = [
    "AuthorityKernel",
    "SecurityAuthority",
    "handleApplicationRequest",
    "configuredTenants",
    "applyCommittedDeletion",
    "cloudflare:workers",
    "reserve_secret_save",
    "delete_account",
  ];
  for (const probe of probes)
    assert.equal(
      bundle.includes(probe),
      false,
      "the CLI bundle must not contain " + probe,
    );
});
