import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const distributedPackages = ["@1password/sdk", "@1password/sdk-core", "jose"];
const sections = [];
for (const name of distributedPackages) {
  const path = "node_modules/" + name + "/package.json";
  const metadata = JSON.parse(await readFile(path, "utf8"));
  let text = "";
  for (const licenseFile of [
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENCE",
  ]) {
    try {
      text = await readFile("node_modules/" + name + "/" + licenseFile, "utf8");
      break;
    } catch {
      // Some published packages include SPDX metadata but omit the license file.
    }
  }
  if (!text && metadata.license === "MIT") {
    text = `MIT License\n\nCopyright (c) 2024 ${metadata.author ?? name}\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.`;
  }
  sections.push(
    `${name}@${metadata.version} — ${metadata.license}\n\n${text.trim()}`,
  );
}
await mkdir("dist", { recursive: true });
await writeFile(
  "dist/THIRD-PARTY-NOTICES.txt",
  sections.join("\n\n---\n\n") + "\n",
);
const cliPath = "dist/cli.mjs";
const cli = await readFile(cliPath, "utf8");
const notices = await readFile("dist/THIRD-PARTY-NOTICES.txt", "utf8");
const publishedCli =
  cli + "\nconst THIRD_PARTY_NOTICES = " + JSON.stringify(notices) + ";\n";
await writeFile(cliPath, publishedCli);
await copyFile(cliPath, "web/public/cli.mjs");
await writeFile(
  "src/generated/cli.ts",
  "export const CLI_MJS_SHA256 = " +
    JSON.stringify(
      createHash("sha256").update(publishedCli).digest("base64url"),
    ) +
    ";\n",
);
