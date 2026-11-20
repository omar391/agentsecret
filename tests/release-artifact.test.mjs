import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url).pathname;
const packageJson = JSON.parse(await readFile(root + "package.json", "utf8"));
const releaseTag = "v" + packageJson.version;

test("CLI release tag must exactly match the locked package version", () => {
  const valid = spawnSync(process.execPath, ["scripts/check-release-tag.mjs"], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, RELEASE_TAG: releaseTag },
  });
  assert.equal(valid.status, 0, valid.stderr);

  const [major, minor, patch] = packageJson.version.split(".").map(Number);
  const otherPatchTag = "v" + [major, minor, patch + 1].join(".");
  for (const tag of [
    releaseTag.slice(1),
    releaseTag + "-preview.1",
    releaseTag + ".1",
    otherPatchTag,
  ]) {
    const invalid = spawnSync(
      process.execPath,
      ["scripts/check-release-tag.mjs"],
      {
        cwd: root,
        encoding: "utf8",
        env: { ...process.env, RELEASE_TAG: tag },
      },
    );
    assert.notEqual(invalid.status, 0, tag + " must be refused");
  }
});

test("CLI release workflow pins actions and verifies provenance before publishing", async () => {
  const workflow = await readFile(
    `${root}.github/workflows/cli-release.yml`,
    "utf8",
  );
  const actionPins = [...workflow.matchAll(/^\s+uses: [^\s@]+@([^\s#]+)/gm)];
  assert.ok(actionPins.length >= 3);
  assert.ok(actionPins.every(([, pin]) => /^[0-9a-f]{40}$/i.test(pin)));
  // Resolved against the upstream v7.0.1 tag, rather than only checking syntax.
  assert.equal(
    (
      workflow.match(
        /actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/g,
      ) || []
    ).length,
    2,
  );
  assert.match(workflow, /npm ci\s+npm --prefix web ci/);
  assert.match(workflow, /subject-path: dist\/cli\.mjs/);
  assert.match(workflow, /--signer-workflow "\$SIGNER_WORKFLOW"/);
  assert.match(workflow, /dist\/cli-tampered\.mjs/);
  assert.match(workflow, /gh release create "\$RELEASE_TAG" dist\/cli\.mjs/);
  assert.match(workflow, /git merge-base --is-ancestor/);
  assert.match(workflow, /release:\n\s+needs: validate-source/);
  assert.match(
    workflow,
    /Run typecheck and full test suite[\s\S]+?npm run typecheck[\s\S]+?npm test/,
  );
  assert.ok(
    workflow.indexOf("npm test") <
      workflow.indexOf("Attest CLI build provenance"),
  );
  const readOnlyJob = workflow.split("  release:\n", 1)[0];
  assert.match(readOnlyJob, /permissions:\n\s+contents: read/);
  assert.doesNotMatch(
    readOnlyJob,
    /id-token:\s*write|attestations:\s*write|contents:\s*write/,
  );
});
