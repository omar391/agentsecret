import { build } from "esbuild";
import { mkdir } from "node:fs/promises";

await mkdir("dist/server", { recursive: true });
await build({
  entryPoints: ["src/server/index.ts"],
  bundle: true,
  packages: "external",
  platform: "node",
  format: "esm",
  target: "node22",
  outfile: "dist/server/index.mjs",
});
