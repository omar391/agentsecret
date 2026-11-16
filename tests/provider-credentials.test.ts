import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AccountBoundProviderCredentials,
  type CredentialBackend,
  type ProviderCredentialBinding,
} from "../cli/provider-credentials";

class MemoryCredentialBackend implements CredentialBackend {
  readonly values = new Map<string, string>();

  read(key: string): string | undefined {
    return this.values.get(key);
  }

  write(key: string, value: string): void {
    this.values.set(key, value);
  }

  delete(key: string): void {
    this.values.delete(key);
  }
}

class FailAfterWriteBackend extends MemoryCredentialBackend {
  failNextWrite = false;

  write(key: string, value: string): void {
    if (this.failNextWrite) {
      this.failNextWrite = false;
      this.values.set(key, "corrupt synthetic record");
      throw new Error("synthetic keychain write interruption");
    }
    super.write(key, value);
  }
}

const binding: ProviderCredentialBinding = {
  server: "https://agentsecret.example.invalid",
  tenant: "tenant-synthetic-a",
  connectionId: "connection-synthetic-a",
  connectionRevision: 1,
  providerMode: "onepassword-service-account",
};

test("provider credentials are partitioned by origin, tenant, connection, revision, and mode", async () => {
  const backend = new MemoryCredentialBackend();
  const store = new AccountBoundProviderCredentials(backend);
  const modes = [
    "bitwarden-secrets-manager",
    "bitwarden-password-manager",
    "onepassword-connect",
    "onepassword-service-account",
    "lastpass",
  ] as const;
  for (const providerMode of modes) {
    await store.put(
      { ...binding, providerMode },
      `synthetic-${providerMode}-token`,
    );
  }
  assert.equal(backend.values.size, modes.length);
  for (const providerMode of modes) {
    assert.equal(
      await store.get({ ...binding, providerMode }),
      `synthetic-${providerMode}-token`,
    );
  }
  assert.equal(
    await store.get({ ...binding, tenant: "tenant-synthetic-b" }),
    undefined,
  );
  assert.equal(
    await store.get({ ...binding, connectionId: "connection-synthetic-b" }),
    undefined,
  );
  assert.equal(
    await store.get({ ...binding, connectionRevision: 2 }),
    undefined,
  );
  assert.equal(
    await store.get({ ...binding, server: "https://other.example.invalid" }),
    undefined,
  );
  const nextRevision = { ...binding, connectionRevision: 2 };
  await store.put(nextRevision, "synthetic-next-revision-token");
  assert.equal(
    await store.get(binding),
    "synthetic-onepassword-service-account-token",
  );
  assert.equal(await store.get(nextRevision), "synthetic-next-revision-token");

  await store.delete(binding);
  assert.equal(await store.get(binding), undefined);
});

test("provider credential binding mismatch and invalid remote origin fail closed", async () => {
  const backend = new MemoryCredentialBackend();
  const store = new AccountBoundProviderCredentials(backend);
  await store.put(binding, "synthetic-provider-token");
  const key = [...backend.values.keys()][0]!;
  backend.values.set(
    key,
    JSON.stringify({
      schema: "agentsecret/provider-credential/v2",
      binding: { ...binding, tenant: "tenant-other" },
      credential: "synthetic-provider-token",
    }),
  );
  await assert.rejects(
    store.get(binding),
    /provider_credential_binding_mismatch/,
  );
  backend.values.set(
    key,
    JSON.stringify({
      schema: "agentsecret/provider-credential/v1",
      binding: {
        server: binding.server,
        tenant: binding.tenant,
        connectionId: binding.connectionId,
        providerMode: binding.providerMode,
      },
      credential: "synthetic-legacy-token",
    }),
  );
  await assert.rejects(
    store.get(binding),
    /provider_credential_binding_mismatch/,
  );
  await assert.rejects(
    store.put({ ...binding, server: "http://untrusted.example" }, "synthetic"),
    /provider_credential_binding_invalid/,
  );
  await assert.rejects(
    store.put({ ...binding, connectionRevision: 0 }, "synthetic"),
    /provider_credential_binding_invalid/,
  );
  await assert.rejects(store.put(binding, ""), /provider_credential_invalid/);
});

test("failed provider credential replacement preserves the previous binding", async () => {
  const backend = new FailAfterWriteBackend();
  const store = new AccountBoundProviderCredentials(backend);
  await store.put(binding, "synthetic-previous-token");
  backend.failNextWrite = true;

  await assert.rejects(
    store.put(binding, "synthetic-replacement-token"),
    /provider_credential_store_write_failed/,
  );
  assert.equal(await store.get(binding), "synthetic-previous-token");
});
