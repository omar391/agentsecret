import { build } from "esbuild";
import { mkdir, readFile, writeFile, copyFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { gzipSync } from "node:zlib";

await mkdir("dist", { recursive: true });
await build({
  entryPoints: ["cli/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  outfile: "dist/cli.mjs",
  banner: {
    js: 'import { createRequire as sdkCreateRequire } from "node:module"; const require = sdkCreateRequire(import.meta.url);',
  },
  plugins: [
    {
      name: "onepassword-inline-wasm",
      setup(build) {
        build.onLoad(
          { filter: /sdk-core[/\\]nodejs[/\\]core\.js$/ },
          async ({ path }) => {
            const source = await readFile(path, "utf8");
            const loader =
              "const path = require('path').join(__dirname, 'core_bg.wasm');\nconst bytes = require('fs').readFileSync(path);";
            // Fail on upstream loader changes rather than emitting a broken artifact.
            if (!source.includes(loader))
              throw new Error("onepassword_wasm_loader_changed");
            const wasm = gzipSync(
              await readFile(join(dirname(path), "core_bg.wasm")),
            );
            return {
              contents: source.replace(
                loader,
                `const bytes = require('node:zlib').gunzipSync(Buffer.from(${JSON.stringify(wasm.toString("base64"))}, 'base64'));`,
              ),
              loader: "js",
              resolveDir: dirname(path),
            };
          },
        );
      },
    },
  ],
});
const source = await readFile("dist/cli.mjs");
await mkdir("src/generated", { recursive: true });
await writeFile(
  "src/generated/cli.ts",
  "export const CLI_MJS_SHA256 = " +
    JSON.stringify(createHash("sha256").update(source).digest("base64url")) +
    ";\n",
);
// The standalone SDK includes its WASM. Serve the CLI as an asset so that its
// binary payload does not count against the free Worker script-size limit.
await mkdir("web/public", { recursive: true });
await copyFile("dist/cli.mjs", "web/public/cli.mjs");
