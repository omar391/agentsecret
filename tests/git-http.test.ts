import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
import { test } from "node:test";
import { inspectGitHttpResponse } from "../src/security/git-http";

const credential = "synthetic-git-http-credential-value";
const upload = "application/x-git-upload-pack-result";
const receive = "application/x-git-receive-pack-result";
const advert = "application/x-git-upload-pack-advertisement";
const flush = Buffer.from("0000"),
  delim = Buffer.from("0001");
function pkt(value: Buffer | string): Buffer {
  const data = Buffer.from(value);
  return Buffer.concat([
    Buffer.from((data.length + 4).toString(16).padStart(4, "0")),
    data,
  ]);
}
function side(channel: number, value: Buffer | string): Buffer {
  return pkt(Buffer.concat([Buffer.from([channel]), Buffer.from(value)]));
}
function pack(value: Buffer | string): Buffer {
  const data = Buffer.from(value),
    header = Buffer.alloc(12);
  header.write("PACK");
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(1, 8);
  let n = data.length,
    next = (3 << 4) | (n & 15);
  n = Math.floor(n / 16);
  const bytes: number[] = [];
  while (n) {
    bytes.push(next | 128);
    next = n & 127;
    n = Math.floor(n / 128);
  }
  bytes.push(next);
  const body = Buffer.concat([header, Buffer.from(bytes), deflateSync(data)]);
  return Buffer.concat([body, createHash("sha1").update(body).digest()]);
}

test("Git HTTP v0 raw and fragmented sideband packs preserve every byte", () => {
  const bytes = pack(Buffer.from([0, 255, 1, 128, 2, 0, 254]));
  for (const wire of [
    Buffer.concat([pkt("NAK\n"), bytes]),
    Buffer.concat([
      pkt("NAK\n"),
      side(1, bytes.subarray(0, 2)),
      side(1, bytes.subarray(2)),
      flush,
    ]),
  ]) {
    const before = Buffer.from(wire),
      result = inspectGitHttpResponse(wire, upload, [credential]);
    assert.equal(result.objectCount, 1);
    assert.equal(result.packBytes, bytes.length);
    assert.deepEqual(wire, before);
  }
});
test("Git HTTP v2 sideband-all handles split UTF-8 progress and packfile sections", () => {
  const bytes = pack("safe content"),
    progress = Buffer.from("Δ progress\n");
  const wire = Buffer.concat([
    side(1, "acknowledgments\n"),
    side(1, "NAK\n"),
    delim,
    side(2, progress.subarray(0, 1)),
    side(1, "packfile\n"),
    side(2, progress.subarray(1)),
    side(1, bytes),
    flush,
    Buffer.from("0002"),
  ]);
  assert.equal(
    inspectGitHttpResponse(wire, upload, [credential]).objectCount,
    1,
  );
});
test("Git HTTP inspects compressed objects before allowing delivery", () => {
  const wire = Buffer.concat([
    pkt("NAK\n"),
    side(1, pack(credential.repeat(4))),
    flush,
  ]);
  assert.equal(wire.includes(Buffer.from(credential)), false);
  assert.throws(
    () => inspectGitHttpResponse(wire, upload, [credential]),
    /git_pack_credential_reflection/,
  );
});
test("Git HTTP refuses progress reflections split across pkt-line headers", () => {
  const wire = Buffer.concat([
    side(2, credential.slice(0, 13)),
    side(2, credential.slice(13)),
    flush,
  ]);
  assert.equal(wire.includes(Buffer.from(credential)), false);
  assert.throws(
    () => inspectGitHttpResponse(wire, upload, [credential]),
    /git_pack_credential_reflection/,
  );
  const encoded = Buffer.concat([
    side(2, Buffer.from(credential).toString("base64")),
    flush,
  ]);
  assert.throws(
    () => inspectGitHttpResponse(encoded, upload, [credential]),
    /git_pack_credential_reflection/,
  );
});
test("Git receive-pack nested status frames cannot hide reflected credentials", () => {
  const inner = Buffer.concat([
    pkt(credential.slice(0, 10)),
    pkt(credential.slice(10)),
    flush,
  ]);
  const wire = Buffer.concat([
    side(1, inner.subarray(0, 7)),
    side(1, inner.subarray(7)),
    flush,
  ]);
  assert.throws(
    () => inspectGitHttpResponse(wire, receive, [credential]),
    /git_pack_credential_reflection/,
  );
  const safe = Buffer.concat([
    side(
      1,
      Buffer.concat([pkt("unpack ok\n"), pkt("ok refs/heads/main\n"), flush]),
    ),
    flush,
  ]);
  assert.equal(
    inspectGitHttpResponse(safe, receive, [credential]).packBytes,
    0,
  );
});
test("Git HTTP rejects malformed framing, unsupported media and external pack URIs", () => {
  for (const wire of [
    Buffer.from("0003"),
    Buffer.from("ffff"),
    Buffer.from("0008x"),
    Buffer.from("zzzz"),
    Buffer.concat([Buffer.from("0002"), flush]),
    side(2, Buffer.from([255])),
  ])
    assert.throws(
      () => inspectGitHttpResponse(wire, upload, [credential]),
      /git_http_invalid/,
    );
  assert.throws(
    () =>
      inspectGitHttpResponse(flush, "application/octet-stream", [credential]),
    /git_http_unsupported/,
  );
  for (const wire of [pkt("packfile-uris\n"), side(1, "packfile-uris\n")])
    assert.throws(
      () => inspectGitHttpResponse(wire, upload, [credential]),
      /git_http_unsupported/,
    );
  assert.throws(
    () => inspectGitHttpResponse(side(1, pack("safe")), advert, [credential]),
    /git_http_invalid/,
  );
});
test("Git HTTP enforces body, frame and credential-target bounds", () => {
  assert.throws(
    () =>
      inspectGitHttpResponse(Buffer.alloc(512 * 1024 + 1), upload, [
        credential,
      ]),
    /git_http_limit_exceeded/,
  );
  assert.throws(
    () =>
      inspectGitHttpResponse(
        Buffer.concat(Array.from({ length: 4097 }, () => Buffer.from("0004"))),
        upload,
        [credential],
      ),
    /git_http_limit_exceeded/,
  );
  assert.throws(
    () => inspectGitHttpResponse(flush, upload, []),
    /git_pack_invalid/,
  );
  assert.throws(
    () =>
      inspectGitHttpResponse(flush, upload, [credential], "invalid" as never),
    /git_http_invalid/,
  );
});
test("real Git v0 and v2 upload-pack streams pass byte-preserving inspection", async (t) => {
  const root = fileURLToPath(new URL("../tmp/", import.meta.url));
  await mkdir(root, { recursive: true });
  const dir = await mkdtemp(join(root, "git-http-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const repo = join(dir, "repo"),
    hooks = join(dir, "hooks"),
    config = join(dir, "gitconfig");
  await mkdir(hooks);
  await writeFile(config, "");
  assert.deepEqual(await readdir(hooks), []);
  const env = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_")),
    ),
    GIT_CONFIG_GLOBAL: config,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_AUTHOR_NAME: "Synthetic",
    GIT_AUTHOR_EMAIL: "synthetic@example.invalid",
    GIT_COMMITTER_NAME: "Synthetic",
    GIT_COMMITTER_EMAIL: "synthetic@example.invalid",
  };
  const flags = ["-c", "core.hooksPath=" + hooks, "-c", "core.fsmonitor=false"];
  execFileSync("git", [...flags, "init", "--template=" + hooks, repo], {
    env,
    stdio: "pipe",
  });
  const git = (args: string[], input?: Buffer, version?: string) =>
    execFileSync("git", [...flags, "-C", repo, ...args], {
      env: { ...env, ...(version ? { GIT_PROTOCOL: version } : {}) },
      input,
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 1024 * 1024,
    });
  const data = Buffer.alloc(300000);
  for (let at = 0; at < data.length; at += 32)
    createHash("sha256").update(String(at)).digest().copy(data, at);
  await writeFile(join(repo, "blob.bin"), data);
  git(["add", "blob.bin"]);
  git(["commit", "-m", "Synthetic fixture"]);
  const oid = git(["rev-parse", "HEAD"]).toString().trim();
  const requests: [Buffer, string?][] = [
    [
      Buffer.concat([
        pkt("want " + oid + " side-band-64k ofs-delta\n"),
        flush,
        pkt("done\n"),
      ]),
    ],
    [
      Buffer.concat([
        pkt("command=fetch\n"),
        delim,
        pkt("want " + oid + "\n"),
        pkt("done\n"),
        flush,
      ]),
      "version=2",
    ],
  ];
  for (const [request, version] of requests) {
    const wire = git(["upload-pack", "--stateless-rpc", "."], request, version),
      before = Buffer.from(wire);
    const result = inspectGitHttpResponse(wire, upload, [credential]);
    assert.equal(result.objectCount, 3);
    assert.ok(result.packBytes > 250000);
    assert.deepEqual(wire, before);
  }
});
test("local workerd applies Git HTTP pack inspection without returning values", async (t) => {
  const { build } = await import("esbuild"),
    { Miniflare, convertV4MiniflareOptions } = await import("miniflare");
  const safe = Buffer.concat([
      pkt("packfile\n"),
      side(1, pack("safe")),
      flush,
    ]).toString("base64"),
    bad = Buffer.concat([
      pkt("packfile\n"),
      side(1, pack(credential)),
      flush,
    ]).toString("base64");
  const bundled = await build({
    stdin: {
      contents: `import {Buffer} from 'node:buffer';import {inspectGitHttpResponse} from './src/security/git-http';export default {fetch(r){try{const b=Buffer.from(new URL(r.url).pathname==='/bad'?${JSON.stringify(bad)}:${JSON.stringify(safe)},'base64');return Response.json(inspectGitHttpResponse(b,${JSON.stringify(upload)},[${JSON.stringify(credential)}]));}catch(e){return Response.json({error:e.code},{status:502});}}};`,
      resolveDir: fileURLToPath(new URL("../", import.meta.url)),
    },
    bundle: true,
    write: false,
    format: "esm",
    platform: "neutral",
    external: ["node:buffer", "node:crypto", "node:zlib"],
  });
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: "git-http",
          modules: true,
          script: bundled.outputFiles[0].text,
          compatibilityDate: "2026-10-23",
          compatibilityFlags: ["nodejs_compat"],
        },
      ],
    }),
  );
  t.after(() => mf.dispose());
  assert.equal(
    (await mf.dispatchFetch("https://fixture.invalid/safe")).status,
    200,
  );
  const denied = await mf.dispatchFetch("https://fixture.invalid/bad");
  assert.equal(denied.status, 502);
  const text = await denied.text();
  assert.match(text, /git_pack_credential_reflection/);
  assert.equal(text.includes(credential), false);
});
