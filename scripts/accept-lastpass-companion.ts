import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  rm,
  rmdir,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  LastPassAdapter,
  serializeLastPassProfile,
} from "../cli/providers/lastpass";
import {
  type AccountBoundProviderCredentials,
  type ProviderCredentialBinding,
} from "../cli/provider-credentials";

async function main(): Promise<void> {
  if (process.platform !== "darwin")
    throw new Error("lastpass_companion_acceptance_requires_macos");

  // Confirm the locally installed companion without printing its output.
  const version = execFileSync("lpass", ["--version"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 10_000,
  });
  assert.match(version, /^LastPass CLI v\d/);

  const root = join(homedir(), ".local", "share", "agentsecret", "lastpass");
  let rootCreated = false;
  try {
    await lstat(root);
  } catch (error) {
    if (
      !(error instanceof Error) ||
      !("code" in error) ||
      error.code !== "ENOENT"
    )
      throw new Error("lastpass_companion_root_unavailable");
    await mkdir(root, { recursive: true, mode: 0o700 });
    rootCreated = true;
  }

  let profileHome: string | undefined;
  try {
    profileHome = await mkdtemp(join(root, ".acceptance-"));
    await chmod(profileHome, 0o700);
    const binding: ProviderCredentialBinding = {
      server: `https://lastpass-acceptance-${randomUUID()}.invalid`,
      tenant: "synthetic-tenant",
      connectionId: "empty-profile-check",
      connectionRevision: 1,
      providerMode: "lastpass",
    };
    const storedProfile = serializeLastPassProfile(
      profileHome,
      "synthetic@example.invalid",
    );
    const credentials = {
      get: async () => storedProfile,
    } as unknown as AccountBoundProviderCredentials;
    const adapter = new LastPassAdapter(binding, credentials);

    let credentialConsumerCalled = false;
    await assert.rejects(
      adapter.withResolvedField("1#/password", async () => {
        credentialConsumerCalled = true;
      }),
      (error: unknown) =>
        error instanceof Error &&
        error.message.startsWith("lastpass_") &&
        !error.message.includes("synthetic@example.invalid"),
    );
    assert.equal(credentialConsumerCalled, false);
    assert.deepEqual(await readdir(profileHome), []);
    console.log(
      "LastPass companion refusal passed: isolated empty profile stayed unauthenticated; no item or value was read.",
    );
  } finally {
    if (profileHome) await rm(profileHome, { recursive: true, force: true });
    if (rootCreated) await rmdir(root).catch(() => {});
  }
}

main().catch(() => {
  console.error(
    "LastPass companion acceptance failed; no provider account or item was accessed.",
  );
  process.exitCode = 1;
});
