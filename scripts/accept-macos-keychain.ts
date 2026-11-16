import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { exportJWK } from "jose";

async function main() {
  if (process.platform !== "darwin")
    throw new Error("This acceptance command requires macOS.");

  const directory = mkdtempSync(
    path.join(tmpdir(), "agentsecret-keychain-acceptance-"),
  );
  chmodSync(directory, 0o700);
  const previousConfigDirectory = process.env.AGENTSECRET_CONFIG_DIR;
  process.env.AGENTSECRET_CONFIG_DIR = directory;

  let saved = false;
  let cleared = false;
  let providerSaved = false;
  let providerCleared = false;
  let providerBinding:
    | {
        server: string;
        tenant: string;
        connectionId: string;
        connectionRevision: number;
        providerMode: "onepassword-service-account";
      }
    | undefined;
  try {
    const [{ createSigningPair, restoreSigningPair }, store] =
      await Promise.all([import("../cli/keys"), import("../cli/store")]);
    const { macOsKeychainProviderCredentials } =
      await import("../cli/provider-credentials");
    const pair = await createSigningPair();
    const privateJwk = await exportJWK(pair.privateKey);
    const server = `https://keychain-acceptance-${randomUUID()}.invalid`;

    store.save(
      {
        server,
        accessToken: "synthetic-keychain-acceptance-token",
        expiresAt: Date.now() + 60_000,
        tenant: "synthetic-keychain-acceptance",
      },
      privateJwk,
    );
    saved = true;

    const profile = store.load();
    assert.equal(profile?.server, server);
    assert.equal(
      JSON.stringify(store.privateKey(server)),
      JSON.stringify(privateJwk),
    );

    const restored = await restoreSigningPair(store.privateKey(server));
    const challenge = crypto.getRandomValues(new Uint8Array(48));
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      restored.privateKey,
      challenge,
    );
    assert.equal(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        restored.publicKey,
        signature,
        challenge,
      ),
      true,
    );

    const providerCredentials = macOsKeychainProviderCredentials();
    providerBinding = {
      server,
      tenant: "synthetic-keychain-acceptance",
      connectionId: "synthetic-provider-binding",
      connectionRevision: 1,
      providerMode: "onepassword-service-account" as const,
    };
    providerSaved = true;
    await providerCredentials.put(
      providerBinding,
      "synthetic-provider-credential-only",
    );
    assert.equal(
      await providerCredentials.get(providerBinding),
      "synthetic-provider-credential-only",
    );
    assert.equal(
      await providerCredentials.get({
        ...providerBinding,
        providerMode: "bitwarden-password-manager",
      }),
      undefined,
    );
    await providerCredentials.delete(providerBinding);
    providerSaved = false;
    providerCleared = true;
    assert.equal(await providerCredentials.get(providerBinding), undefined);

    store.clear();
    saved = false;
    cleared = true;
    assert.equal(store.load(), null);
    assert.throws(() => store.privateKey(server));
    console.log(
      "macOS Keychain acceptance passed: synthetic signing key and provider credential restored, binding-checked, and removed.",
    );
  } finally {
    if (saved && !cleared) {
      const store = await import("../cli/store");
      store.clear();
    }
    if (providerSaved && !providerCleared && providerBinding) {
      const { macOsKeychainProviderCredentials } =
        await import("../cli/provider-credentials");
      await macOsKeychainProviderCredentials().delete(providerBinding);
    }
    if (cleared || !saved) rmSync(directory, { recursive: true, force: true });
    if (previousConfigDirectory === undefined)
      delete process.env.AGENTSECRET_CONFIG_DIR;
    else process.env.AGENTSECRET_CONFIG_DIR = previousConfigDirectory;
  }
}

main().catch(() => {
  console.error(
    "macOS Keychain acceptance failed; no provider account was accessed.",
  );
  process.exitCode = 1;
});
