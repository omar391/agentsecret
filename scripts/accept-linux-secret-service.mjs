import { build } from "esbuild";
import { mkdtemp, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

const root = fileURLToPath(new URL("../", import.meta.url));
const temporary = await mkdtemp(
  path.join(tmpdir(), "agentsecret-linux-accept-"),
);
const image = `agentsecret-linux-store-acceptance:${randomUUID()}`;
const bundle = path.join(temporary, "linux-secret-service-acceptance.mjs");

try {
  await build({
    entryPoints: [
      path.join(root, "scripts/linux-secret-service-acceptance.ts"),
    ],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    outfile: bundle,
  });
  execFileSync(
    "docker",
    [
      "build",
      "--quiet",
      "--file",
      "scripts/linux-secret-service.Dockerfile",
      "--tag",
      image,
      ".",
    ],
    { cwd: root, stdio: "inherit" },
  );
  execFileSync(
    "docker",
    [
      "run",
      "--rm",
      "--network=none",
      "--mount",
      `type=bind,source=${bundle},target=/opt/linux-secret-service-acceptance.mjs,readonly`,
      image,
    ],
    { cwd: root, stdio: "inherit" },
  );
} finally {
  try {
    execFileSync("docker", ["image", "rm", image], { stdio: "ignore" });
  } catch {
    // A failed build may not have created the unique image tag.
  }
  await rm(temporary, { recursive: true, force: true });
}
