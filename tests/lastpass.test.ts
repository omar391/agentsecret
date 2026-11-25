import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  AccountBoundProviderCredentials,
  type CredentialBackend,
  type ProviderCredentialBinding,
} from "../cli/provider-credentials";
import {
  LastPassAdapter,
  serializeLastPassProfile,
  type LastPassRunner,
} from "../cli/providers/lastpass";

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
  tenant: "tenant-synthetic-lastpass",
  connectionId: "lastpass-synthetic-connection",
  connectionRevision: 2,
  providerMode: "lastpass",
};
const accountId = "1234567890123456789";
const password = "synthetic-lastpass-secret";

function profileHome(): string {
  const root = join(homedir(), ".local", "share", "agentsecret", "lastpass");
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const folder = mkdtempSync(join(root, "test-"));
  chmodSync(folder, 0o700);
  return folder;
}

function runner(overrides: Partial<LastPassRunner> = {}): LastPassRunner {
  return {
    async status() {
      return "Logged in as isolated@example.invalid.\n";
    },
    async showItem(_home, requestedId) {
      assert.equal(requestedId, accountId);
      return JSON.stringify([
        {
          id: accountId,
          username: "synthetic-user",
          password,
          note: "synthetic note",
          url: "https://example.invalid",
        },
      ]);
    },
    async listItems() {
      return "2026-11-16 (none)/Synthetic item [id: 1234567890123456789] [username: ]\n";
    },
    ...overrides,
  };
}

async function adapterFor(
  profile: string,
  testRunner: LastPassRunner,
): Promise<LastPassAdapter> {
  const credentials = new AccountBoundProviderCredentials(
    new MemoryCredentialBackend(),
  );
  await credentials.put(
    binding,
    serializeLastPassProfile(profile, "isolated@example.invalid"),
  );
  return new LastPassAdapter(binding, credentials, testRunner);
}

test("LastPass resolves only an exact item field inside the bound profile", async (t) => {
  const home = profileHome();
  t.after(() => rmSync(home, { recursive: true, force: true }));
  let requestedHome = "";
  const adapter = await adapterFor(
    home,
    runner({
      async status(profile) {
        requestedHome = profile;
        return "Logged in as isolated@example.invalid.\n";
      },
      async showItem(profile, id) {
        assert.equal(profile, home);
        assert.equal(id, accountId);
        return JSON.stringify([
          {
            id,
            username: "synthetic-user",
            password,
            note: "synthetic note",
          },
        ]);
      },
    }),
  );

  const safeResult = await adapter.withResolvedField(
    `${accountId}#/password`,
    async (value) => value.length,
  );
  assert.equal(safeResult, password.length);
  assert.equal(requestedHome, home);
  await assert.rejects(
    adapter.withResolvedField(`${accountId}#/url`, async (value) => value),
    /lastpass_reference_invalid/,
  );
});

test("LastPass refuses a profile identity mismatch before reading an item", async (t) => {
  const home = profileHome();
  t.after(() => rmSync(home, { recursive: true, force: true }));
  let itemRead = false;
  const adapter = await adapterFor(
    home,
    runner({
      async status() {
        return "Logged in as other@example.invalid.\n";
      },
      async showItem() {
        itemRead = true;
        return "[]";
      },
    }),
  );
  await assert.rejects(
    adapter.withResolvedField(`${accountId}#/password`, async (value) => value),
    /lastpass_profile_mismatch/,
  );
  assert.equal(itemRead, false);
});

test("LastPass rejects malformed, duplicate, or mismatched exact item results", async (t) => {
  const home = profileHome();
  t.after(() => rmSync(home, { recursive: true, force: true }));
  for (const output of [
    "not-json",
    "[]",
    JSON.stringify([
      { id: accountId, password },
      { id: accountId, password },
    ]),
    JSON.stringify([{ id: "1111111111111111111", password }]),
  ]) {
    const adapter = await adapterFor(
      home,
      runner({
        async showItem() {
          return output;
        },
      }),
    );
    await assert.rejects(
      adapter.withResolvedField(
        `${accountId}#/password`,
        async (value) => value,
      ),
      /lastpass_item_(?:invalid|mismatch)/,
    );
  }
});

test("LastPass profile paths are owner-only and scoped to AgentSecret", (t) => {
  const external = mkdtempSync(join(homedir(), "lastpass-external-"));
  t.after(() => rmSync(external, { recursive: true, force: true }));
  chmodSync(external, 0o700);
  assert.throws(
    () => serializeLastPassProfile(external, "isolated@example.invalid"),
    /lastpass_profile_invalid/,
  );
});

test("LastPass refuses profile overrides and aliases that could change CLI behavior", async (t) => {
  const home = profileHome();
  t.after(() => rmSync(home, { recursive: true, force: true }));
  writeFileSync(join(home, "env"), "LPASS_ASKPASS=/tmp/untrusted\n", {
    mode: 0o600,
  });
  const adapter = await adapterFor(home, runner());
  await assert.rejects(
    adapter.withResolvedField(`${accountId}#/password`, async (value) => value),
    /lastpass_profile_unsafe_configuration/,
  );
});

test("LastPass creates, updates, and ensures through the bound noninteractive profile", async (t) => {
  const home = profileHome();
  t.after(() => rmSync(home, { recursive: true, force: true }));
  let stored = {
    id: accountId,
    name: "Synthetic item",
    username: "synthetic-user",
    password,
    note: "synthetic note",
  };
  const observations: string[] = [];
  let updateCalls = 0;
  let itemCreated = false;
  const adapter = await adapterFor(home, {
    async status(profile) {
      observations.push("status:" + profile);
      return "Logged in as isolated@example.invalid.\n";
    },
    async showItem(profile, id) {
      observations.push("show:" + id);
      return JSON.stringify([stored]);
    },
    async listItems(profile) {
      observations.push("list:" + profile);
      return itemCreated
        ? "2026-11-16 (none)/Synthetic item [id: " +
            accountId +
            "] [username: ]\n"
        : "";
    },
    async createItem(profile, name, notes) {
      observations.push("create:" + name + ":" + notes);
      itemCreated = true;
      return "";
    },
    async updateField(profile, id, field, value) {
      observations.push("update:" + id + ":" + field + ":" + value);
      stored = { ...stored, [field === "note" ? "note" : field]: value };
    },
  });

  const created = await adapter.createSecret("Synthetic item", password);
  assert.deepEqual(created, {
    status: "created",
    reference: accountId + "#/password",
    verified: true,
  });
  assert.equal(JSON.stringify(created).includes(password), false);

  const updated = await adapter.updateField(
    accountId + "#/password",
    "new-password",
  );
  assert.deepEqual(updated, {
    status: "updated",
    reference: accountId + "#/password",
    verified: true,
  });

  const unchanged = await adapter.ensureField(
    accountId + "#/password",
    "new-password",
  );
  assert.equal(unchanged.status, "unchanged");
  assert.deepEqual(observations, [
    "status:" + home,
    "list:" + home,
    "create:Synthetic item:" + password,
    "list:" + home,
    "show:" + accountId,
    "status:" + home,
    "show:" + accountId,
    "update:" + accountId + ":password:new-password",
    "show:" + accountId,
    "status:" + home,
    "show:" + accountId,
  ]);
});

test("LastPass write results are reference-only and ambiguous outcomes stay unknown", async (t) => {
  const home = profileHome();
  t.after(() => rmSync(home, { recursive: true, force: true }));
  let createdOnce = false;
  const adapter = await adapterFor(home, {
    async status() {
      return "Logged in as isolated@example.invalid.\n";
    },
    async showItem() {
      return JSON.stringify([
        {
          id: accountId,
          name: "Synthetic item",
          password: "different",
          username: "synthetic-user",
        },
      ]);
    },
    async createItem() {
      createdOnce = true;
      return "";
    },
    async listItems() {
      return createdOnce
        ? "2026-11-16 (none)/Synthetic item [id: 2222222222222222222]\n2026-11-16 (none)/Synthetic item [id: 3333333333333333333]\n"
        : "";
    },
    async updateField() {},
  });
  await assert.rejects(
    adapter.createSecret("Synthetic item", password),
    /lastpass_create_outcome_unknown/,
  );
  await assert.rejects(
    adapter.updateField(accountId + "#/password", "new-password"),
    /lastpass_update_outcome_unknown/,
  );
});

test("LastPass update ignores managed timestamps but catches changed siblings", async (t) => {
  const home = profileHome();
  t.after(() => rmSync(home, { recursive: true, force: true }));
  let stored = {
    id: accountId,
    name: "Synthetic item",
    username: "synthetic-user",
    password,
    note: "synthetic note",
    url: "https://example.invalid",
    last_modified_gmt: "1794850000",
    last_touch: "0",
  };
  let updateCalls = 0;
  const adapter = await adapterFor(home, {
    async status() {
      return "Logged in as isolated@example.invalid.\n";
    },
    async showItem() {
      return JSON.stringify([stored]);
    },
    async updateField(_home, _id, field, value) {
      updateCalls += 1;
      stored = {
        ...stored,
        [field]: value,
        // The second sync also changes a sibling that the command never
        // claimed to touch, which the read-back comparison must catch.
        ...(updateCalls === 2 ? { username: "unexpected-user" } : {}),
        last_modified_gmt: "1794859999",
        last_touch: "1",
      };
    },
  });
  const updated = await adapter.updateField(
    accountId + "#/password",
    "new-password",
  );
  assert.equal(updated.status, "updated");

  await assert.rejects(
    adapter.updateField(accountId + "#/password", "another-password"),
    /lastpass_update_outcome_unknown/,
  );
});

test("LastPass create polls past a transient unresolved listing", async (t) => {
  const home = profileHome();
  t.after(() => rmSync(home, { recursive: true, force: true }));
  let listings = 0;
  const adapter = await adapterFor(home, {
    async status() {
      return "Logged in as isolated@example.invalid.\n";
    },
    async showItem() {
      return JSON.stringify([
        {
          id: accountId,
          name: "Synthetic item",
          password,
          username: "synthetic-user",
        },
      ]);
    },
    async listItems() {
      listings += 1;
      if (listings < 3)
        return "2026-11-16 (none)/Synthetic item [id: 0] [username: ]\n";
      return (
        "2026-11-16 (none)/Synthetic item [id: " +
        accountId +
        "] [username: ]\n"
      );
    },
    async createItem() {
      return "";
    },
    async updateField() {},
  });
  const created = await adapter.createSecret("Synthetic item", password);
  assert.equal(created.status, "created");
  assert.equal(listings, 3);
});
