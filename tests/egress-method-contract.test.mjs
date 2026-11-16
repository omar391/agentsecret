import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function quotedMethods(source) {
  return [...source.matchAll(/"([A-Z]+)"/g)].map((match) => match[1]);
}

test("Rust runtime egress methods stay aligned with the cloud broker", async () => {
  const [broker, native] = await Promise.all([
    readFile(path.join(root, "src/broker.ts"), "utf8"),
    readFile(
      path.join(root, "native/agentsecret-supervisor/src/lib.rs"),
      "utf8",
    ),
  ]);
  const brokerBlock = broker.match(
    /p\.allowedMethods\.some\([\s\S]*?!\s*\[([^\]]+)\]\.includes\(/,
  );
  const nativeBlock = native.match(
    /pub fn is_supported_http_method\(method: &str\) -> bool\s*\{([\s\S]*?)\n\}/,
  );
  assert.ok(brokerBlock, "cloud broker method allowlist is present");
  assert.ok(nativeBlock, "native supervisor method allowlist is present");

  const brokerMethods = quotedMethods(brokerBlock[1]).sort();
  const nativeMethods = quotedMethods(nativeBlock[1]).sort();
  assert.equal(new Set(brokerMethods).size, brokerMethods.length);
  assert.equal(new Set(nativeMethods).size, nativeMethods.length);
  assert.deepEqual(nativeMethods, brokerMethods);
});
