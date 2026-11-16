import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const root = fileURLToPath(new URL("../../", import.meta.url));
const output = join(root, "web", "public");
const archiveManifestPath = join(root, ".agentsecret-source-manifest.json");
let revision;
let files;
try {
  const gitRoot = execFileSync(
    "git",
    ["-C", root, "rev-parse", "--show-toplevel"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  ).trim();
  if (resolve(gitRoot) !== resolve(root)) throw new Error("not_a_git_root");
  revision = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: root,
    encoding: "utf8",
  }).trim();
  files = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], {
    cwd: root,
    encoding: "buffer",
  })
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
} catch {
  const manifest = JSON.parse(await readFile(archiveManifestPath, "utf8"));
  if (typeof manifest.revision !== "string" || !Array.isArray(manifest.files))
    throw new Error("source_archive_manifest_invalid");
  revision = manifest.revision;
  files = manifest.files;
}
files = files
  .filter((path) => {
    const absolutePath = resolve(root, path);
    const configuredDataDir = process.env.AGENTSECRET_DATA_DIR
      ? resolve(root, process.env.AGENTSECRET_DATA_DIR)
      : null;
    const under = (directory) => {
      const relativePath = relative(directory, absolutePath);
      return (
        relativePath === "" ||
        (relativePath !== ".." && !relativePath.startsWith(".." + sep))
      );
    };
    return (
      !under(resolve(root, "data")) &&
      !(configuredDataDir && under(configuredDataDir)) &&
      path !== ".agentsecret-source-manifest.json" &&
      !path.startsWith("docs/evidence/") &&
      path !== "docs/key-custody-and-rotation.md" &&
      path !== "dev-learnings.md" &&
      ![
        "web/public/source.tar.gz",
        "web/public/source.tar.gz.sha256",
        "web/public/source-revision.json",
      ].includes(path)
    );
  })
  .sort();

await mkdir(output, { recursive: true });
const archive = join(output, "source.tar.gz");
const staging = await mkdtemp(join(tmpdir(), "agentsecret-source-"));
const treeHash = createHash("sha256");
try {
  for (const path of files) {
    const source = join(root, path);
    const target = join(staging, "agentsecret-" + revision, path);
    await mkdir(join(target, ".."), { recursive: true });
    await copyFile(source, target);
    treeHash.update(path + "\0");
    treeHash.update(await readFile(source));
  }
  const archiveManifest = { revision, files };
  await writeFile(
    join(
      staging,
      "agentsecret-" + revision,
      ".agentsecret-source-manifest.json",
    ),
    JSON.stringify(archiveManifest, null, 2) + "\n",
  );
  execFileSync("tar", ["-czf", archive, "-C", staging, "."], {
    cwd: root,
    stdio: "inherit",
  });
} finally {
  await rm(staging, { recursive: true, force: true });
}
const digest = createHash("sha256")
  .update(await readFile(archive))
  .digest("hex");
await writeFile(
  join(output, "source.tar.gz.sha256"),
  digest + "  source.tar.gz\n",
);
await writeFile(
  join(output, "source-revision.json"),
  JSON.stringify(
    { revision, sourceTreeSha256: treeHash.digest("hex"), sha256: digest },
    null,
    2,
  ) + "\n",
);
const distribution = join(root, "web", "dist");
await mkdir(distribution, { recursive: true });
for (const name of [
  "source.tar.gz",
  "source.tar.gz.sha256",
  "source-revision.json",
])
  await copyFile(join(output, name), join(distribution, name));
