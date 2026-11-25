import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("the reported product version matches package.json", async () => {
  const pkg = JSON.parse(await read("package.json"));
  const source = await read("src/version.ts");
  const match = /export const VERSION = "([^"]+)";/.exec(source);
  assert.ok(match, "src/version.ts exports VERSION");
  assert.equal(match[1], pkg.version);
});

test("version reporting sites use VERSION instead of a literal", async () => {
  for (const path of [
    "src/core/application.ts",
    "src/mcp/protocol.ts",
    "cli/index.ts",
    "cli/providers/onepassword-service-account.ts",
  ]) {
    const source = await read(path);
    assert.ok(source.includes("VERSION"), path + " imports VERSION");
    assert.doesNotMatch(
      source,
      /(?:version|integrationVersion):\s*"\d+\.\d+\.\d+"/,
      path,
    );
  }
});
