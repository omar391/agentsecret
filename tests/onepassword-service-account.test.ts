import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ItemCategory,
  ItemFieldType,
  type Item,
  type ItemCreateParams,
} from "@1password/sdk";
import {
  AccountBoundProviderCredentials,
  type CredentialBackend,
  type ProviderCredentialBinding,
} from "../cli/provider-credentials";
import {
  OnePasswordServiceAccountAdapter,
  serializeOnePasswordServiceAccountProfile,
  type OnePasswordClient,
} from "../cli/providers/onepassword-service-account";

class MemoryCredentialBackend implements CredentialBackend {
  values = new Map<string, string>();
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
  connectionId: "op-service-account-1",
  connectionRevision: 1,
  providerMode: "onepassword-service-account",
};
const vaultId = "vault_synthetic_1";
const itemId = "item_synthetic_1";
const secretValue = "synthetic-provider-secret";

function item(
  fields: Item["fields"],
  id = itemId,
  title = "Synthetic API credential",
): Item {
  return {
    id,
    title,
    category: ItemCategory.ApiCredentials,
    vaultId,
    fields,
    sections: [],
    notes: "",
    tags: [],
    websites: [],
    version: 1,
    files: [],
    createdAt: new Date(0),
    updatedAt: new Date(0),
  };
}

function fakeClient(seed: Item[] = []): OnePasswordClient {
  const items = new Map(
    seed.map((entry) => [entry.id, structuredClone(entry)]),
  );
  let nextItem = 0;
  return {
    vaults: {
      async getOverview(id) {
        if (id !== vaultId) throw new Error("denied");
        return { id };
      },
    },
    items: {
      async get(id, requestedItemId) {
        if (id !== vaultId) throw new Error("denied");
        const found = items.get(requestedItemId);
        if (!found) throw new Error("not found");
        return structuredClone(found);
      },
      async create(params: ItemCreateParams) {
        if (params.vaultId !== vaultId) throw new Error("denied");
        const created = item(
          params.fields || [],
          `item_created_${++nextItem}`,
          params.title,
        );
        items.set(created.id, structuredClone(created));
        return created;
      },
      async put(updated) {
        if (updated.vaultId !== vaultId || !items.has(updated.id))
          throw new Error("denied");
        const stored = {
          ...structuredClone(updated),
          version: updated.version + 1,
        };
        items.set(updated.id, stored);
        return structuredClone(stored);
      },
    },
  };
}

async function adapterFor(client: OnePasswordClient) {
  const credentials = new AccountBoundProviderCredentials(
    new MemoryCredentialBackend(),
  );
  await credentials.put(
    binding,
    serializeOnePasswordServiceAccountProfile(
      "synthetic-service-account-token",
      vaultId,
    ),
  );
  return new OnePasswordServiceAccountAdapter(
    binding,
    credentials,
    async (token) => {
      assert.equal(token, "synthetic-service-account-token");
      return client;
    },
  );
}

test("1Password service-account credential verification checks only the pinned vault", async () => {
  const adapter = await adapterFor(fakeClient());
  assert.equal(await adapter.verifyVaultAccess(), true);
});

test("1Password service account resolves only the exact item field in process", async () => {
  const client = fakeClient([
    item([
      {
        id: "secret_field",
        title: "credential",
        fieldType: ItemFieldType.Concealed,
        value: secretValue,
      },
      {
        id: "display_name",
        title: "display name",
        fieldType: ItemFieldType.Text,
        value: "synthetic",
      },
    ]),
  ]);
  const adapter = await adapterFor(client);

  const safeResult = await adapter.withResolvedField(
    itemId,
    "secret_field",
    async (value) => value.length,
  );

  assert.equal(safeResult, secretValue.length);
  assert.equal(JSON.stringify(safeResult).includes(secretValue), false);
  await assert.rejects(
    adapter.withResolvedField(itemId, "wrong_field", async (value) => value),
    /onepassword_service_account_field_unavailable/,
  );
});

test("1Password create and update return reference-only receipts with readback", async () => {
  const client = fakeClient();
  const adapter = await adapterFor(client);
  const created = await adapter.createItem({
    category: ItemCategory.ApiCredentials,
    vaultId,
    title: "Synthetic item",
    fields: [
      {
        id: "api_token",
        title: "API token",
        fieldType: ItemFieldType.Concealed,
        sectionId: "credentials",
        value: secretValue,
      },
    ],
    sections: [{ id: "credentials", title: "Credentials" }],
  });
  assert.deepEqual(created, {
    status: "created",
    vaultId,
    itemId: "item_created_1",
  });
  assert.equal(JSON.stringify(created).includes(secretValue), false);

  const updated = await adapter.updateField(
    created.itemId,
    "api_token",
    "synthetic-updated-token",
  );
  assert.deepEqual(updated, {
    status: "updated",
    vaultId,
    itemId: created.itemId,
    fieldId: "api_token",
  });
});

test("1Password local secret helpers create, ensure, and return reference-only results", async () => {
  const client = fakeClient();
  const adapter = await adapterFor(client);
  const created = await adapter.createSecret(
    "Synthetic local secret",
    secretValue,
  );
  assert.equal(created.status, "created");
  assert.equal(created.reference, `${created.itemId}#/fields/secret`);
  assert.equal(JSON.stringify(created).includes(secretValue), false);

  const unchanged = await adapter.ensureField(created.reference, secretValue);
  assert.equal(unchanged.status, "unchanged");
  assert.equal(unchanged.reference, created.reference);

  const changedValue = "synthetic-updated-local-secret";
  const updated = await adapter.ensureField(created.reference, changedValue);
  assert.equal(updated.status, "updated");
  assert.equal(updated.reference, created.reference);
  assert.equal(JSON.stringify(updated).includes(changedValue), false);
  await adapter.withResolvedField(created.itemId, "secret", async (observed) =>
    assert.equal(observed, changedValue),
  );
});

test("1Password service-account deletion requires a custom field and verifies absence", async () => {
  const client = fakeClient([
    item([
      {
        id: "username",
        title: "username",
        fieldType: ItemFieldType.Text,
        value: "synthetic-user",
      },
      {
        id: "custom_token",
        title: "custom token",
        fieldType: ItemFieldType.Concealed,
        sectionId: "custom",
        value: secretValue,
      },
    ]),
  ]);
  const adapter = await adapterFor(client);

  await assert.rejects(
    adapter.deleteCustomField(itemId, "username"),
    /onepassword_service_account_builtin_field_refused/,
  );
  const deleted = await adapter.deleteCustomField(itemId, "custom_token");
  assert.deepEqual(deleted, {
    status: "deleted",
    vaultId,
    itemId,
    fieldId: "custom_token",
  });
});

test("1Password mutations surface ambiguous provider outcomes without error details", async () => {
  const client = fakeClient();
  client.items.create = async (params) => {
    await fakeClient([
      item(params.fields || [], "item_possible_commit"),
    ]).items.get(vaultId, "item_possible_commit");
    throw new Error(`transport failed after sending ${secretValue}`);
  };
  const adapter = await adapterFor(client);

  await assert.rejects(
    adapter.createItem({
      category: ItemCategory.ApiCredentials,
      vaultId,
      title: "Synthetic ambiguous item",
      fields: [
        {
          id: "api_token",
          title: "API token",
          fieldType: ItemFieldType.Concealed,
          value: secretValue,
        },
      ],
    }),
    (error: unknown) =>
      error instanceof Error &&
      error.message === "onepassword_service_account_create_outcome_unknown" &&
      !error.message.includes(secretValue),
  );
});
