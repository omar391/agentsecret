import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { GitPackError, inspectGitPack } from "../src/security/git-pack";

const canary = "fixture-" + "privatevalue";
const hash = (bytes: Uint8Array, algorithm = "sha1") =>
  createHash(algorithm).update(bytes).digest();
function header(type: number, size: number): Buffer {
  const bytes = [(type << 4) | (size & 15)];
  size = Math.floor(size / 16);
  if (size) bytes[0] |= 128;
  while (size) {
    const next = size % 128;
    size = Math.floor(size / 128);
    bytes.push(next | (size ? 128 : 0));
  }
  return Buffer.from(bytes);
}
function entry(type: number, data: Buffer, base = Buffer.alloc(0)): Buffer {
  return Buffer.concat([header(type, data.length), base, deflateSync(data)]);
}
function pack(
  entries: Buffer[],
  algorithm: "sha1" | "sha256" = "sha1",
): Buffer {
  const head = Buffer.alloc(12);
  head.write("PACK");
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(entries.length, 8);
  const data = Buffer.concat([head, ...entries]);
  return Buffer.concat([data, hash(data, algorithm)]);
}
function blobId(data: Buffer, algorithm = "sha1") {
  return createHash(algorithm)
    .update(`blob ${data.length}\0`)
    .update(data)
    .digest();
}
const rejects = (bytes: Buffer, code: string) =>
  assert.throws(
    () => inspectGitPack(bytes, [canary]),
    (error) =>
      error instanceof GitPackError &&
      error.code === code &&
      !error.message.includes(canary),
  );

test("pack inspection preserves binary bytes and supports explicit SHA-1 and SHA-256", () => {
  const binary = Buffer.from(Array.from({ length: 256 }, (_, n) => n));
  for (const algorithm of ["sha1", "sha256"] as const) {
    const bytes = pack([entry(3, binary)], algorithm);
    const original = Buffer.from(bytes);
    assert.deepEqual(inspectGitPack(bytes, [canary], algorithm), {
      objectCount: 1,
      deltaObjects: 0,
      decodedBytes: 256,
    });
    assert.deepEqual(bytes, original);
  }
});

test("compressed credential and encoded/escaped reflections are refused without data in errors", () => {
  for (const value of [
    canary,
    Buffer.from(canary).toString("base64"),
    JSON.stringify({ value: canary }).replace("fixture", "\\u0066ixture"),
  ]) {
    rejects(
      pack([entry(3, Buffer.from(value))]),
      "git_pack_credential_reflection",
    );
  }
});

test("a credential assembled only after REF-delta reconstruction is refused", () => {
  const base = Buffer.from("fixture-safe");
  const suffix = Buffer.from("privatevalue");
  const delta = Buffer.concat([
    Buffer.from([base.length, canary.length, 0x90, 8, suffix.length]),
    suffix,
  ]);
  assert.equal(base.includes(canary), false);
  assert.equal(delta.includes(canary), false);
  rejects(
    pack([entry(3, base), entry(7, delta, blobId(base))]),
    "git_pack_credential_reflection",
  );
});

test("forward REF-deltas and OFS-deltas resolve correctly", () => {
  const base = Buffer.from("base bytes");
  const delta = Buffer.from([base.length, base.length, 0x90, base.length]);
  const ref = entry(7, delta, blobId(base));
  assert.equal(
    inspectGitPack(pack([ref, entry(3, base)]), [canary]).objectCount,
    2,
  );
  const baseEntry = entry(3, base);
  assert.ok(baseEntry.length < 128);
  assert.equal(
    inspectGitPack(
      pack([baseEntry, entry(6, delta, Buffer.from([baseEntry.length]))]),
      [canary],
    ).objectCount,
    2,
  );
});

test("thin packs, invalid delta copies and reserved delta operations fail closed", () => {
  const base = Buffer.from("base bytes");
  const valid = Buffer.from([base.length, base.length, 0x90, base.length]);
  rejects(pack([entry(7, valid, blobId(base))]), "git_pack_missing_base");
  for (const bad of [
    Buffer.from([base.length, 1, 0]),
    Buffer.from([base.length, 1, 0x91, 127, 1]),
    Buffer.from([base.length, 1, 2, 65]),
  ]) {
    rejects(
      pack([entry(3, base), entry(7, bad, blobId(base))]),
      "git_pack_invalid",
    );
  }
});

test("checksum corruption, truncation, trailing data and unsupported types are refused", () => {
  const valid = pack([entry(3, Buffer.from("safe binary"))]);
  const corrupt = Buffer.from(valid);
  corrupt[corrupt.length - 1] ^= 1;
  for (const bytes of [
    corrupt,
    valid.subarray(0, valid.length - 1),
    Buffer.concat([valid, Buffer.from([0])]),
    pack([entry(5, Buffer.from("bad type"))]),
  ])
    rejects(bytes, "git_pack_invalid");
});

test("object and pack budgets are enforced before unbounded decompression", () => {
  const data = Buffer.concat([
    Buffer.from("PACK"),
    Buffer.from([0, 0, 0, 2, 0, 0, 0, 1]),
    header(3, 8 * 1024 * 1024 + 1),
    deflateSync(Buffer.from("x")),
  ]);
  rejects(Buffer.concat([data, hash(data)]), "git_pack_limit_exceeded");
  rejects(Buffer.alloc(512 * 1024 + 1), "git_pack_limit_exceeded");
});

test("object count and delta-depth bounds are enforced", () => {
  const head = Buffer.alloc(12);
  head.write("PACK");
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(1025, 8);
  rejects(Buffer.concat([head, hash(head)]), "git_pack_limit_exceeded");
  let base = Buffer.from("base");
  const entries = [entry(3, base)];
  for (let n = 0; n < 33; n++) {
    const next = Buffer.from("object-" + n);
    const delta = Buffer.concat([
      Buffer.from([base.length, next.length, next.length]),
      next,
    ]);
    entries.push(entry(7, delta, blobId(base)));
    base = next;
  }
  rejects(pack(entries), "git_pack_limit_exceeded");
});

test("real Git-generated pack with an inside-pack delta passes byte-preserving inspection", (t) => {
  const root = fileURLToPath(new URL("../", import.meta.url));
  mkdirSync(join(root, "tmp"), { recursive: true });
  const folder = mkdtempSync(join(root, "tmp/git-pack-test-"));
  chmodSync(folder, 0o700);
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const hooks = join(folder, "empty-hooks");
  mkdirSync(hooks);
  const git = (args: string[], input?: Uint8Array) =>
    execFileSync("git", ["-c", "core.hooksPath=" + hooks, ...args], {
      cwd: folder,
      input,
      env: {
        ...process.env,
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
  git(["init", "-q"]);
  const first = Buffer.alloc(300_000);
  let state = 0x235713;
  for (let n = 0; n < first.length; n++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    first[n] = state & 255;
  }
  const second = Buffer.from(first);
  second.fill(42, 140_000, 140_300);
  const ids = [first, second].map((bytes) =>
    git(["hash-object", "-w", "--stdin"], bytes).toString().trim(),
  );
  const packed = git(
    ["pack-objects", "--stdout", "--window=250", "--depth=50"],
    Buffer.from(ids.join("\n") + "\n"),
  );
  const original = Buffer.from(packed);
  const result = inspectGitPack(packed, [canary]);
  assert.equal(result.objectCount, 2);
  assert.equal(result.deltaObjects, 1);
  assert.deepEqual(packed, original);
});

test("local workerd inspects zlib streams and refuses reconstructed credential reflections", async (t) => {
  const { build } = await import("esbuild");
  const { Miniflare, convertV4MiniflareOptions } = await import("miniflare");
  const root = fileURLToPath(new URL("../", import.meta.url));
  const bundled = await build({
    stdin: {
      contents: `
    import { Buffer } from 'node:buffer';
    import { inspectGitPack, GitPackError } from './src/security/git-pack';
    export default { async fetch(request) {
      const input = await request.json();
      try { return Response.json(inspectGitPack(Buffer.from(input.pack, 'base64'), input.secrets)); }
      catch (error) { return Response.json({ error: error instanceof GitPackError ? error.code : 'inspection_failed' }, { status: 403 }); }
    } };`,
      resolveDir: root,
      loader: "ts",
    },
    bundle: true,
    write: false,
    format: "esm",
    platform: "browser",
    external: ["node:buffer", "node:crypto", "node:zlib"],
  });
  const worker = new Miniflare(
    await convertV4MiniflareOptions({
      workers: [
        {
          name: "pack-inspection",
          modules: true,
          script: bundled.outputFiles[0].text,
          compatibilityDate: "2026-10-23",
          compatibilityFlags: ["nodejs_compat"],
        },
      ],
    }),
  );
  t.after(() => worker.dispose());
  const base = Buffer.from("fixture-safe");
  const suffix = Buffer.from("privatevalue");
  const delta = Buffer.concat([
    Buffer.from([base.length, canary.length, 0x90, 8, suffix.length]),
    suffix,
  ]);
  for (const [bytes, expectedStatus] of [
    [pack([entry(3, base)]), 200],
    [pack([entry(3, base), entry(7, delta, blobId(base))]), 403],
  ] as const) {
    const response = await worker.dispatchFetch("http://localhost/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pack: bytes.toString("base64"),
        secrets: [canary],
      }),
    });
    assert.equal(response.status, expectedStatus);
    const text = await response.text();
    assert.equal(text.includes(canary), false);
    if (expectedStatus === 403)
      assert.equal(JSON.parse(text).error, "git_pack_credential_reflection");
  }
});
