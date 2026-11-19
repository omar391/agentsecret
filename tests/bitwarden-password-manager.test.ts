import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AccountBoundProviderCredentials,
  type CredentialBackend,
  type ProviderCredentialBinding,
} from "../cli/provider-credentials";
import {
  BitwardenPasswordManagerAdapter,
  bitwardenPasswordManagerCustomFieldPath,
  bitwardenPasswordManagerReference,
  serializeFastflowBitwardenProfile,
  type BitwardenPasswordManagerRunner,
} from "../cli/providers/bitwarden-password-manager";

class MemoryCredentialBackend implements CredentialBackend {
  private readonly values = new Map<string, string>();
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

const binding: ProviderCredentialBinding = {
  server: "https://agentsecret.example.invalid",
  tenant: "tenant-synthetic-a",
  connectionId: "connection-synthetic-a",
  connectionRevision: 3,
  providerMode: "bitwarden-password-manager",
};
const itemId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const password = "synthetic-password-value";
const profileIdentity = {
  userId: "synthetic-user-id",
  userEmail: "bwpm@example.invalid",
  serverUrl: "https://vault.bitwarden.com",
};

function runnerFor(
  item: unknown,
  observed: string[] = [],
): BitwardenPasswordManagerRunner {
  return {
    async ensureSession(appName) {
      observed.push(`ensure:${appName}`);
      return profileIdentity;
    },
    async readItem(appName, requestedId) {
      observed.push(`read:${appName}:${requestedId}`);
      return JSON.stringify(item);
    },
    async createItem(appName, encodedItem) {
      observed.push(`create:${appName}:${encodedItem}`);
      return JSON.stringify({
        id: itemId,
        type: 1,
        name: "Synthetic item",
        login: { password: "unused" },
        fields: [],
      });
    },
    async editItem(appName, requestedId, encodedItem) {
      observed.push(`edit:${appName}:${requestedId}:${encodedItem}`);
      return JSON.stringify(item);
    },
  };
}

async function adapterFor(
  runner: BitwardenPasswordManagerRunner,
  profileName = "agentsecret-test-profile",
) {
  const credentials = new AccountBoundProviderCredentials(
    new MemoryCredentialBackend(),
  );
  await credentials.put(
    binding,
    serializeFastflowBitwardenProfile(profileName, profileIdentity),
  );
  return new BitwardenPasswordManagerAdapter(binding, credentials, runner);
}

test("Bitwarden Password Manager resolves one exact login field through the enrolled Fastflow profile", async () => {
  const observed: string[] = [];
  const adapter = await adapterFor(
    runnerFor(
      {
        id: itemId,
        type: 1,
        login: { username: "user@example.invalid", password },
        fields: [],
      },
      observed,
    ),
  );
  const reference = bitwardenPasswordManagerReference(
    itemId,
    "/login/password",
  );
  const result = await adapter.withResolvedField(reference, async (value) => {
    assert.equal(value, password);
    return { status: "available", reference };
  });
  assert.deepEqual(result, { status: "available", reference });
  assert.deepEqual(observed, [
    "ensure:agentsecret-test-profile",
    `read:agentsecret-test-profile:${itemId}`,
  ]);
});

test("Fastflow profile binding records the confirmed account identity without session material", () => {
  const serialized = serializeFastflowBitwardenProfile(
    "agentsecret-test-profile",
    profileIdentity,
  );
  assert.deepEqual(JSON.parse(serialized), {
    schema: "agentsecret/fastflow-bitwarden-profile/v1",
    appName: "agentsecret-test-profile",
    userId: "synthetic-user-id",
    userEmail: "bwpm@example.invalid",
    serverUrl: "https://vault.bitwarden.com",
  });
  assert.doesNotMatch(serialized, /BW_SESSION|masterPassword|apiKey/);
  assert.throws(
    () =>
      serializeFastflowBitwardenProfile("agentsecret-test-profile", {
        ...profileIdentity,
        serverUrl: "http://untrusted.example.invalid",
      }),
    /bitwarden_password_manager_profile_invalid/,
  );
});

test("Bitwarden Password Manager selects a uniquely named custom field and rejects ambiguity", async () => {
  const customPath = bitwardenPasswordManagerCustomFieldPath("API/Key");
  assert.equal(customPath, "/fields/API%2FKey");
  const reference = bitwardenPasswordManagerReference(itemId, customPath);
  const item = {
    id: itemId,
    type: 1,
    login: { password: "unused" },
    fields: [{ name: "API/Key", value: password }],
  };
  const adapter = await adapterFor(runnerFor(item));
  assert.equal(
    await adapter.withResolvedField(reference, async (value) => value),
    password,
  );

  const duplicate = await adapterFor(
    runnerFor({
      ...item,
      fields: [
        { name: "API/Key", value: password },
        { name: "API/Key", value: "second-value" },
      ],
    }),
  );
  await assert.rejects(
    duplicate.withResolvedField(reference, async () => "must-not-run"),
    /bitwarden_password_manager_field_unavailable/,
  );
});

test("Bitwarden Password Manager refuses malformed refs, mismatched items, and missing local profiles", async () => {
  let calls = 0;
  const runner: BitwardenPasswordManagerRunner = {
    async ensureSession() {
      calls += 1;
      return profileIdentity;
    },
    async readItem() {
      calls += 1;
      return "{}";
    },
  };
  const adapter = await adapterFor(runner);
  await assert.rejects(
    adapter.withResolvedField(
      `${itemId.toUpperCase()}#/login/password`,
      async () => "",
    ),
    /bitwarden_password_manager_reference_invalid/,
  );
  await assert.rejects(
    adapter.withResolvedField(
      bitwardenPasswordManagerReference(itemId, "/login/password"),
      async () => "",
    ),
    /bitwarden_password_manager_item_invalid/,
  );
  assert.equal(calls, 2);

  const emptyCredentials = new AccountBoundProviderCredentials(
    new MemoryCredentialBackend(),
  );
  const unconfigured = new BitwardenPasswordManagerAdapter(
    binding,
    emptyCredentials,
    runner,
  );
  await assert.rejects(
    unconfigured.withResolvedField(
      bitwardenPasswordManagerReference(itemId, "/login/password"),
      async () => "",
    ),
    /bitwarden_password_manager_profile_unconfigured/,
  );
  assert.equal(calls, 2);

  const mismatchedRunner: BitwardenPasswordManagerRunner = {
    async ensureSession() {
      return { ...profileIdentity, userId: "another-synthetic-user" };
    },
    async readItem() {
      calls += 1;
      return JSON.stringify({
        id: itemId,
        type: 1,
        login: { password },
        fields: [],
      });
    },
  };
  const mismatchedProfile = await adapterFor(mismatchedRunner);
  await assert.rejects(
    mismatchedProfile.withResolvedField(
      bitwardenPasswordManagerReference(itemId, "/login/password"),
      async () => "must-not-run",
    ),
    /bitwarden_password_manager_profile_mismatch/,
  );
  assert.equal(calls, 2, "a different Fastflow account must not read the item");
});

test("Bitwarden Password Manager creates a login item through stdin and returns a reference-only receipt", async () => {
  const observed: string[] = [];
  const item = {
    id: itemId,
    type: 1,
    name: "Synthetic item",
    login: { password },
    fields: [],
  };
  const adapter = await adapterFor({
    async ensureSession() {
      observed.push("ensure:agentsecret-test-profile");
      return profileIdentity;
    },
    async readItem(appName, requestedId) {
      observed.push("read:" + requestedId);
      return JSON.stringify(item);
    },
    async createItem(appName, encodedItem) {
      const decoded = JSON.parse(
        Buffer.from(encodedItem, "base64").toString("utf8"),
      );
      observed.push("create:" + decoded.login.password);
      return JSON.stringify(item);
    },
    async editItem() {
      observed.push("edit");
      return "{}";
    },
  });
  const created = await adapter.createSecret("Synthetic item", password);
  assert.deepEqual(created, {
    status: "created",
    reference: itemId + "#/login/password",
    verified: true,
  });
  assert.equal(JSON.stringify(created).includes(password), false);
  assert.deepEqual(observed, [
    "ensure:agentsecret-test-profile",
    "create:" + password,
    "read:" + itemId,
  ]);
});

test("Bitwarden Password Manager updates one exact field while preserving sibling fields", async () => {
  const observed: string[] = [];
  const item = {
    id: itemId,
    type: 1,
    name: "Synthetic item",
    login: {
      username: "sibling-username",
      password: "old-password",
      uris: [{ uri: "https://example.invalid" }],
    },
    fields: [
      { name: "API/Key", value: "sibling-custom-field", type: 0 },
      { name: "Other", value: "unchanged", type: 0 },
    ],
  };
  const updatedItem = {
    ...item,
    login: {
      ...item.login,
      password: "new-password",
    },
  };
  const adapter = await adapterFor({
    async ensureSession() {
      return profileIdentity;
    },
    async readItem(appName, requestedId) {
      return JSON.stringify(observed.includes("edited") ? updatedItem : item);
    },
    async createItem() {
      throw new Error("unexpected create");
    },
    async editItem(appName, requestedId, encodedItem) {
      observed.push("edited");
      const decoded = JSON.parse(
        Buffer.from(encodedItem, "base64").toString("utf8"),
      );
      assert.equal(decoded.login.password, "new-password");
      assert.equal(decoded.login.username, "sibling-username");
      return JSON.stringify(updatedItem);
    },
  });
  const updated = await adapter.updateField(
    bitwardenPasswordManagerReference(itemId, "/login/password"),
    "new-password",
  );
  assert.deepEqual(updated, {
    status: "updated",
    reference: itemId + "#/login/password",
    verified: true,
  });
  assert.equal(JSON.stringify(updated).includes("new-password"), false);

  const unchanged = await adapter.ensureField(
    bitwardenPasswordManagerReference(itemId, "/login/password"),
    "new-password",
  );
  assert.equal(unchanged.status, "unchanged");
});

test("Bitwarden Password Manager marks ambiguous write verification as outcome unknown", async () => {
  const adapter = await adapterFor({
    async ensureSession() {
      return profileIdentity;
    },
    async readItem() {
      return JSON.stringify({
        id: itemId,
        type: 1,
        name: "Synthetic item",
        login: { password: "different" },
        fields: [],
      });
    },
    async createItem() {
      return JSON.stringify({
        id: itemId,
        type: 1,
        name: "Synthetic item",
        login: { password },
        fields: [],
      });
    },
    async editItem() {
      return JSON.stringify({
        id: itemId,
        type: 1,
        name: "Synthetic item",
        login: { password: "different" },
        fields: [],
      });
    },
  });
  await assert.rejects(
    adapter.createSecret("Synthetic item", password),
    /bitwarden_password_manager_create_outcome_unknown/,
  );
  await assert.rejects(
    adapter.updateField(
      bitwardenPasswordManagerReference(itemId, "/login/password"),
      "new-password",
    ),
    /bitwarden_password_manager_update_outcome_unknown/,
  );
});
