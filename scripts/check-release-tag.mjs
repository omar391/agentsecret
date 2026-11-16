import { readFile } from "node:fs/promises";

const releaseTag = process.env.RELEASE_TAG;
if (!releaseTag) throw new Error("RELEASE_TAG is required.");

const packageJson = JSON.parse(await readFile("package.json", "utf8"));
const expectedTag = `v${packageJson.version}`;
if (releaseTag !== expectedTag)
  throw new Error(`Release tag must match package version ${expectedTag}.`);

console.log(`Validated CLI release ${releaseTag}.`);
