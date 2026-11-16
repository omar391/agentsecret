import {
  ItemCategory,
  ItemFieldType,
  type Item,
  type ItemCreateParams,
} from "@1password/sdk";
import {
  AccountBoundProviderCredentials,
  type ProviderCredentialBinding,
} from "../provider-credentials";

export interface OnePasswordClient {
  vaults: {
    getOverview(vaultId: string): Promise<{ id: string }>;
  };
  items: {
    get(vaultId: string, itemId: string): Promise<Item>;
    create(params: ItemCreateParams): Promise<Item>;
    put(item: Item): Promise<Item>;
  };
}

export type OnePasswordClientFactory = (
  serviceAccountToken: string,
) => Promise<OnePasswordClient>;

interface OnePasswordServiceAccountProfile {
  schema: "agentsecret/onepassword-service-account-profile/v1";
  token: string;
  vaultId: string;
}

export function serializeOnePasswordServiceAccountProfile(
  token: string,
  vaultId: string,
): string {
  if (
    typeof token !== "string" ||
    !token ||
    token.length > 8192 ||
    /[\u0000-\u001f\u007f]/.test(token) ||
    !validIdentifier(vaultId)
  )
    throw new Error("onepassword_service_account_profile_invalid");
  return JSON.stringify({
    schema: "agentsecret/onepassword-service-account-profile/v1",
    token,
    vaultId,
  } satisfies OnePasswordServiceAccountProfile);
}

function parseServiceAccountProfile(
  value: string,
): OnePasswordServiceAccountProfile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("onepassword_service_account_profile_invalid");
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.keys(parsed).sort().join(",") !== "schema,token,vaultId" ||
    (parsed as { schema?: unknown }).schema !==
      "agentsecret/onepassword-service-account-profile/v1" ||
    typeof (parsed as { token?: unknown }).token !== "string" ||
    !(parsed as { token: string }).token ||
    typeof (parsed as { vaultId?: unknown }).vaultId !== "string" ||
    !validIdentifier((parsed as { vaultId: string }).vaultId)
  )
    throw new Error("onepassword_service_account_profile_invalid");
  return parsed as OnePasswordServiceAccountProfile;
}

export interface OnePasswordSafeReceipt {
  status: "created" | "updated" | "deleted";
  vaultId: string;
  itemId: string;
  fieldId?: string;
}

export type OnePasswordServiceAccountReference = {
  itemId: string;
  fieldId: string;
};

export function parseOnePasswordServiceAccountReference(
  reference: string,
): OnePasswordServiceAccountReference {
  if (
    typeof reference !== "string" ||
    reference.length > 260 ||
    /[\u0000-\u001f\u007f]/.test(reference)
  )
    throw new Error("onepassword_service_account_reference_invalid");
  const match =
    /^([A-Za-z0-9_-]{1,128})#\/fields\/([A-Za-z0-9_-]{1,128})$/.exec(reference);
  if (!match) throw new Error("onepassword_service_account_reference_invalid");
  return { itemId: match[1]!, fieldId: match[2]! };
}

export function onePasswordServiceAccountReference(
  itemId: string,
  fieldId: string,
): string {
  if (!validIdentifier(itemId) || !validIdentifier(fieldId))
    throw new Error("onepassword_service_account_reference_invalid");
  return `${itemId}#/fields/${fieldId}`;
}

function validIdentifier(value: string): boolean {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    /^[A-Za-z0-9_-]+$/.test(value)
  );
}

function assertSafeItem(item: Item, vaultId: string, itemId: string): void {
  if (
    !item ||
    !validIdentifier(item.id) ||
    item.id !== itemId ||
    item.vaultId !== vaultId ||
    item.category === "SshKey" ||
    item.category === "Unsupported" ||
    !Array.isArray(item.fields) ||
    item.fields.some(
      (field) =>
        field.fieldType === "SshKey" || field.fieldType === "Unsupported",
    )
  )
    throw new Error("onepassword_service_account_item_unsupported");
  const fieldIds = new Set<string>();
  for (const field of item.fields) {
    if (!validIdentifier(field.id) || fieldIds.has(field.id))
      throw new Error("onepassword_service_account_item_unsupported");
    fieldIds.add(field.id);
  }
}

function assertWritableItem(item: Item): void {
  if (
    item.files?.length ||
    item.document ||
    item.category === "SshKey" ||
    item.category === "Unsupported"
  )
    throw new Error("onepassword_service_account_item_unsupported");
}

function exactField(item: Item, fieldId: string) {
  const matches = item.fields.filter((field) => field.id === fieldId);
  if (matches.length !== 1)
    throw new Error("onepassword_service_account_field_unavailable");
  return matches[0]!;
}

function sameUntouchedFields(
  before: Item,
  after: Item,
  fieldId: string,
): boolean {
  const original = before.fields
    .filter((field) => field.id !== fieldId)
    .map((field) => [field.id, field.fieldType, field.value]);
  const returned = after.fields
    .filter((field) => field.id !== fieldId)
    .map((field) => [field.id, field.fieldType, field.value]);
  return JSON.stringify(original) === JSON.stringify(returned);
}

/**
 * Node-only companion adapter for one explicitly selected service-account vault.
 * The token comes from the account-bound OS credential store. Resolved values
 * are passed only to a trusted in-process consumer callback, never returned in
 * a receipt or written to logs.
 */
export class OnePasswordServiceAccountAdapter {
  private clientPromise?: Promise<OnePasswordClient>;
  private vaultVerified = false;
  private vaultId?: string;

  constructor(
    private readonly binding: ProviderCredentialBinding,
    private readonly credentials: AccountBoundProviderCredentials,
    private readonly clientFactory: OnePasswordClientFactory = async (auth) => {
      const { createClient } = await import("@1password/sdk");
      const client = await createClient({
        auth,
        integrationName: "AgentSecret",
        integrationVersion: "3.0.0",
      });
      return client;
    },
  ) {
    if (binding.providerMode !== "onepassword-service-account")
      throw new Error("onepassword_service_account_binding_invalid");
  }

  private async client(): Promise<OnePasswordClient> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        const storedProfile = await this.credentials.get(this.binding);
        if (!storedProfile)
          throw new Error("onepassword_service_account_unconfigured");
        const profile = parseServiceAccountProfile(storedProfile);
        this.vaultId = profile.vaultId;
        return this.clientFactory(profile.token);
      })();
    }
    try {
      const client = await this.clientPromise;
      if (!this.vaultVerified) {
        const vaultId = this.vaultId;
        if (!vaultId)
          throw new Error("onepassword_service_account_unconfigured");
        const vault = await client.vaults.getOverview(vaultId);
        if (vault.id !== vaultId)
          throw new Error("onepassword_service_account_vault_mismatch");
        this.vaultVerified = true;
      }
      return client;
    } catch (error) {
      this.clientPromise = undefined;
      this.vaultVerified = false;
      this.vaultId = undefined;
      if (error instanceof Error && error.message.startsWith("onepassword_"))
        throw error;
      throw new Error("onepassword_service_account_vault_access_failed");
    }
  }

  /** Verify the configured token against the pinned vault without reading items. */
  async verifyVaultAccess(): Promise<true> {
    await this.client();
    return true;
  }

  private async readItem(
    client: OnePasswordClient,
    itemId: string,
  ): Promise<Item> {
    const vaultId = this.vaultId;
    if (!vaultId) throw new Error("onepassword_service_account_unconfigured");
    try {
      const item = await client.items.get(vaultId, itemId);
      assertSafeItem(item, vaultId, itemId);
      return item;
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.startsWith("onepassword_service_account_")
      )
        throw error;
      throw new Error("onepassword_service_account_read_failed");
    }
  }

  async withResolvedField<T>(
    itemId: string,
    fieldId: string,
    consume: (value: string) => Promise<T>,
  ): Promise<T> {
    if (!validIdentifier(itemId) || !validIdentifier(fieldId))
      throw new Error("onepassword_service_account_reference_invalid");
    try {
      const client = await this.client();
      const item = await this.readItem(client, itemId);
      const field = exactField(item, fieldId);
      return await consume(field.value);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("onepassword_"))
        throw error;
      throw new Error("onepassword_service_account_read_failed");
    }
  }

  async createItem(params: ItemCreateParams): Promise<OnePasswordSafeReceipt> {
    if (
      !params ||
      typeof params.title !== "string" ||
      !params.title.trim() ||
      !Array.isArray(params.fields) ||
      params.fields.length === 0 ||
      !validIdentifier(params.category) ||
      params.category === "SshKey" ||
      params.category === "Unsupported" ||
      params.document !== undefined ||
      (params.files !== undefined && params.files.length > 0) ||
      new Set(params.fields.map((field) => field.id)).size !==
        params.fields.length ||
      params.fields?.some(
        (field) =>
          !validIdentifier(field.id) ||
          typeof field.value !== "string" ||
          field.fieldType === "Unsupported" ||
          field.fieldType === "SshKey",
      )
    )
      throw new Error("onepassword_service_account_create_invalid");
    const client = await this.client();
    const vaultId = this.vaultId;
    if (!vaultId || params.vaultId !== vaultId)
      throw new Error("onepassword_service_account_create_invalid");
    let created: Item;
    try {
      created = await client.items.create(params);
    } catch {
      throw new Error("onepassword_service_account_create_outcome_unknown");
    }
    try {
      assertSafeItem(created, vaultId, created.id);
      const observed = await this.readItem(client, created.id);
      assertSafeItem(observed, vaultId, created.id);
      if (
        observed.title !== params.title ||
        observed.category !== params.category ||
        params.fields?.some((expected) => {
          const matches = observed.fields.filter(
            (field) => field.id === expected.id,
          );
          return matches.length !== 1 || matches[0]!.value !== expected.value;
        })
      )
        throw new Error("verification mismatch");
    } catch {
      throw new Error("onepassword_service_account_create_outcome_unknown");
    }
    return {
      status: "created",
      vaultId,
      itemId: created.id,
    };
  }

  async createSecret(
    title: string,
    value: string,
  ): Promise<OnePasswordSafeReceipt & { reference: string }> {
    const normalTitle = title.trim();
    if (
      typeof title !== "string" ||
      title !== normalTitle ||
      !normalTitle ||
      normalTitle.length > 128 ||
      /[\u0000-\u001f\u007f]/.test(normalTitle) ||
      typeof value !== "string" ||
      !value ||
      value.length > 8192
    )
      throw new Error("onepassword_service_account_create_invalid");
    await this.client();
    const vaultId = this.vaultId;
    if (!vaultId) throw new Error("onepassword_service_account_unconfigured");
    const created = await this.createItem({
      category: ItemCategory.ApiCredentials,
      vaultId,
      title: normalTitle,
      fields: [
        {
          id: "secret",
          title: "Secret",
          fieldType: ItemFieldType.Concealed,
          sectionId: "credentials",
          value,
        },
      ],
      sections: [{ id: "credentials", title: "Credentials" }],
    });
    return {
      ...created,
      reference: onePasswordServiceAccountReference(created.itemId, "secret"),
    };
  }

  async ensureField(
    reference: string,
    value: string,
  ): Promise<
    Omit<OnePasswordSafeReceipt, "status"> & {
      reference: string;
      status: "unchanged" | "updated";
    }
  > {
    const parsed = parseOnePasswordServiceAccountReference(reference);
    if (typeof value !== "string" || !value || value.length > 8192)
      throw new Error("onepassword_service_account_update_invalid");
    let current = "";
    await this.withResolvedField(
      parsed.itemId,
      parsed.fieldId,
      async (observed) => {
        current = observed;
      },
    );
    if (current === value)
      return {
        status: "unchanged",
        vaultId: this.vaultId!,
        itemId: parsed.itemId,
        fieldId: parsed.fieldId,
        reference,
      };
    const updated = await this.updateField(
      parsed.itemId,
      parsed.fieldId,
      value,
    );
    return { ...updated, reference, status: "updated" };
  }

  async updateField(
    itemId: string,
    fieldId: string,
    value: string,
  ): Promise<OnePasswordSafeReceipt> {
    if (
      !validIdentifier(itemId) ||
      !validIdentifier(fieldId) ||
      typeof value !== "string" ||
      value.length > 16 * 1024
    )
      throw new Error("onepassword_service_account_update_invalid");
    const client = await this.client();
    const vaultId = this.vaultId;
    if (!vaultId) throw new Error("onepassword_service_account_unconfigured");
    const before = await this.readItem(client, itemId);
    assertWritableItem(before);
    exactField(before, fieldId);
    let updated: Item;
    try {
      updated = await client.items.put({
        ...before,
        fields: before.fields.map((field) =>
          field.id === fieldId ? { ...field, value } : field,
        ),
      });
    } catch {
      throw new Error("onepassword_service_account_update_outcome_unknown");
    }
    try {
      const observed = await this.readItem(client, itemId);
      const field = exactField(observed, fieldId);
      if (
        field.value !== value ||
        updated.vaultId !== vaultId ||
        updated.id !== itemId ||
        !sameUntouchedFields(before, observed, fieldId)
      )
        throw new Error("verification mismatch");
    } catch {
      throw new Error("onepassword_service_account_update_outcome_unknown");
    }
    return { status: "updated", vaultId, itemId, fieldId };
  }

  async deleteCustomField(
    itemId: string,
    fieldId: string,
  ): Promise<OnePasswordSafeReceipt> {
    if (!validIdentifier(itemId) || !validIdentifier(fieldId))
      throw new Error("onepassword_service_account_reference_invalid");
    const client = await this.client();
    const vaultId = this.vaultId;
    if (!vaultId) throw new Error("onepassword_service_account_unconfigured");
    const before = await this.readItem(client, itemId);
    assertWritableItem(before);
    const field = exactField(before, fieldId);
    if (!field.sectionId)
      throw new Error("onepassword_service_account_builtin_field_refused");
    let updated: Item;
    try {
      updated = await client.items.put({
        ...before,
        fields: before.fields.filter((candidate) => candidate.id !== fieldId),
      });
    } catch {
      throw new Error("onepassword_service_account_delete_outcome_unknown");
    }
    try {
      const observed = await this.readItem(client, itemId);
      if (
        observed.fields.some((candidate) => candidate.id === fieldId) ||
        updated.vaultId !== vaultId ||
        updated.id !== itemId ||
        !sameUntouchedFields(before, observed, fieldId)
      )
        throw new Error("verification mismatch");
    } catch {
      throw new Error("onepassword_service_account_delete_outcome_unknown");
    }
    return { status: "deleted", vaultId, itemId, fieldId };
  }
}
