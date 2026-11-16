import type { ConnectLoginFindSelector, VaultConfig } from "../types";
import {
  HttpError,
  parseConnectReference as parseSharedConnectReference,
  readText,
} from "../security/primitives";
import { providerFetch, providerJson } from "../bitwarden/client";

const CONNECT_ID = /^[0-9a-z]{26}$/;
type ConnectConfig = Extract<VaultConfig, { type: "onepassword-connect" }>;

export interface ConnectWriteReceipt {
  itemId: string;
  vaultId: string;
}

export interface ConnectSecretReceipt extends ConnectWriteReceipt {
  reference: string;
  verified: true;
}

export function parseConnectReference(reference: string) {
  const parsed = parseSharedConnectReference(reference);
  if (!parsed) throw new HttpError(400, "invalid_connect_reference");
  return parsed;
}

function jsonPointerSegment(value: string) {
  return value.replace(/~/g, "~0").replace(/\//g, "~1");
}

function itemUrl(config: ConnectConfig, itemId?: string) {
  if (
    !config.apiUrl ||
    !config.vaultId ||
    !CONNECT_ID.test(config.vaultId) ||
    (itemId !== undefined && !CONNECT_ID.test(itemId))
  )
    throw new HttpError(400, "invalid_connect_configuration");
  return `${config.apiUrl}/v1/vaults/${config.vaultId}/items${itemId ? `/${itemId}` : ""}`;
}

async function connectRequest<T = Record<string, any>>(
  config: ConnectConfig,
  path: string,
  method: string,
  body?: unknown,
): Promise<T | null> {
  let response: Response;
  try {
    response = await providerFetch(path, {
      method,
      headers: {
        Authorization: "Bearer " + config.accessToken,
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new HttpError(502, "vault_provider_unavailable");
  }
  if (!response.ok) {
    const status = response.status;
    await response.body?.cancel();
    if (status === 401 || status === 403)
      throw new HttpError(502, "vault_credentials_rejected");
    if (status === 404) throw new HttpError(502, "connect_item_not_found");
    throw new HttpError(502, "vault_provider_rejected_request");
  }
  if (response.status === 204) return null;
  try {
    const result = JSON.parse(await readText(response, 1024 * 1024));
    if (!result || typeof result !== "object") throw new Error();
    return result as T;
  } catch {
    throw new HttpError(502, "invalid_vault_response");
  }
}

/** Resolve one exact title and field without returning provider item metadata. */
export interface ConnectTitleSelection {
  reference: string;
  observedValues: string[];
  title: string;
}

export async function findConnectReferenceByTitle(
  config: ConnectConfig,
  title: string,
  fieldId?: string,
  loginSelector?: ConnectLoginFindSelector,
): Promise<ConnectTitleSelection> {
  const selectedTitle = title;
  if (
    !selectedTitle.trim() ||
    selectedTitle.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(selectedTitle) ||
    (fieldId !== undefined &&
      (!fieldId ||
        fieldId.length > 256 ||
        /[\u0000-\u001f\u007f]/.test(fieldId))) ||
    (loginSelector !== undefined &&
      (loginSelector.title !== selectedTitle ||
        loginSelector.fieldId !== fieldId ||
        !loginSelector.username.trim() ||
        !loginSelector.uris.length ||
        new Set(loginSelector.uris).size !== loginSelector.uris.length))
  )
    throw new HttpError(400, "invalid_secret_selector");

  const listUrl = new URL(itemUrl(config));
  const escapedTitle = selectedTitle
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
  listUrl.searchParams.set("filter", `title eq "${escapedTitle}"`);
  const items = (await providerJson(listUrl.toString(), {
    headers: {
      Authorization: "Bearer " + config.accessToken,
      Accept: "application/json",
    },
  })) as unknown as Record<string, any>[];
  if (!Array.isArray(items)) throw new HttpError(502, "invalid_vault_response");
  const observedValues = [
    selectedTitle,
    ...items.flatMap((item) =>
      Array.isArray(item?.fields)
        ? item.fields
            .map((field: { value?: unknown }) => field?.value)
            .filter(
              (value: unknown): value is string => typeof value === "string",
            )
        : [],
    ),
  ];
  const matches = items.filter(
    (item) =>
      item?.title === selectedTitle &&
      item?.vault?.id === config.vaultId &&
      typeof item?.id === "string" &&
      CONNECT_ID.test(item.id),
  );
  if (matches.length === 0) throw new HttpError(404, "secret_not_found");
  if (matches.length !== 1)
    throw new HttpError(409, "secret_selector_ambiguous");

  const itemId = matches[0].id as string;
  const item = await providerJson(itemUrl(config, itemId), {
    headers: {
      Authorization: "Bearer " + config.accessToken,
      Accept: "application/json",
    },
  });
  if (
    !item ||
    item.id !== itemId ||
    item.vault?.id !== config.vaultId ||
    !Array.isArray(item.fields)
  )
    throw new HttpError(502, "invalid_vault_response");
  if (item.title !== selectedTitle)
    throw new HttpError(409, "secret_selector_changed");
  if (loginSelector) {
    if (item.category !== "LOGIN" || !Array.isArray(item.urls))
      throw new HttpError(409, "secret_selector_changed");
    const usernames = item.fields.filter(
      (field: { purpose?: unknown; value?: unknown }) =>
        field?.purpose === "USERNAME" && typeof field.value === "string",
    );
    const itemUris = item.urls.map((entry: { href?: unknown }) => entry?.href);
    if (
      usernames.length !== 1 ||
      usernames[0].value !== loginSelector.username ||
      itemUris.some((uri: unknown) => typeof uri !== "string") ||
      itemUris.length !== loginSelector.uris.length ||
      loginSelector.uris.some((uri) => !itemUris.includes(uri))
    )
      throw new HttpError(409, "secret_selector_changed");
  }
  observedValues.push(
    ...item.fields
      .map((field: { value?: unknown }) => field?.value)
      .filter((value: unknown): value is string => typeof value === "string"),
  );
  const fields = item.fields.filter(
    (field: {
      id?: unknown;
      purpose?: unknown;
      value?: unknown;
      label?: unknown;
    }) =>
      typeof field?.id === "string" &&
      typeof field.value === "string" &&
      (fieldId === undefined
        ? field.purpose === "PASSWORD"
        : field.id === fieldId) &&
      (!loginSelector ||
        (field.purpose === "PASSWORD" &&
          (loginSelector.fieldPath === undefined ||
            field.label === loginSelector.fieldPath))),
  );
  if (fields.length === 0) throw new HttpError(404, "secret_field_not_found");
  if (fields.length !== 1)
    throw new HttpError(409, "secret_selector_ambiguous");
  const selectedFieldId = fields[0].id as string;
  const reference = itemId + "#" + encodeURIComponent(selectedFieldId);
  if (!parseSharedConnectReference(reference))
    throw new HttpError(400, "invalid_connect_reference");
  return {
    reference,
    observedValues,
    title: selectedTitle,
  };
}

export async function resolveConnect(
  config: ConnectConfig,
  reference: string,
): Promise<string> {
  return (await readConnectReference(config, reference)).value;
}

export async function readConnectReference(
  config: ConnectConfig,
  reference: string,
): Promise<{
  value: string;
  observedValues: string[];
  title: string;
  passwordFieldCount: number;
  selectedFieldPurpose: unknown;
  selectedFieldId: string;
  selectedFieldLabel: unknown;
  category: unknown;
  username?: string;
  usernameFieldCount: number;
  itemUris?: string[];
}> {
  const { itemId, fieldId } = parseConnectReference(reference);
  if (!config.apiUrl || !config.vaultId || !CONNECT_ID.test(config.vaultId))
    throw new HttpError(400, "invalid_connect_reference");
  const item = await providerJson(itemUrl(config, itemId), {
    headers: {
      Authorization: "Bearer " + config.accessToken,
      Accept: "application/json",
    },
  });
  const matches = Array.isArray(item.fields)
    ? item.fields.filter((field: { id?: unknown }) => field?.id === fieldId)
    : [];
  const field = matches.length === 1 ? matches[0] : null;
  if (
    item.id !== itemId ||
    item.vault?.id !== config.vaultId ||
    typeof field?.value !== "string"
  )
    throw new HttpError(502, "connect_field_not_found");
  const usernameFields = item.fields.filter(
    (candidate: { purpose?: unknown; value?: unknown }) =>
      candidate?.purpose === "USERNAME" && typeof candidate.value === "string",
  );
  const itemUris = Array.isArray(item.urls)
    ? item.urls.map((entry: { href?: unknown }) => entry?.href)
    : undefined;
  return {
    value: field.value,
    title: item.title,
    category: item.category,
    username: usernameFields.length === 1 ? usernameFields[0].value : undefined,
    usernameFieldCount: usernameFields.length,
    itemUris:
      itemUris?.every((uri: unknown) => typeof uri === "string") === true
        ? itemUris
        : undefined,
    selectedFieldId: fieldId,
    selectedFieldLabel: field.label,
    passwordFieldCount: item.fields.filter(
      (candidate: { purpose?: unknown }) => candidate?.purpose === "PASSWORD",
    ).length,
    selectedFieldPurpose: field.purpose,
    observedValues: item.fields
      .map((candidate: { value?: unknown }) => candidate?.value)
      .filter((value: unknown): value is string => typeof value === "string"),
  };
}

export async function createConnectItem(
  config: ConnectConfig,
  item: Record<string, unknown>,
): Promise<ConnectWriteReceipt> {
  const vault = item.vault;
  if (
    !vault ||
    typeof vault !== "object" ||
    Array.isArray(vault) ||
    (vault as Record<string, unknown>).id !== config.vaultId
  )
    throw new HttpError(400, "connect_item_vault_mismatch");
  const created = await connectRequest(config, itemUrl(config), "POST", item);
  if (
    !created ||
    typeof created.id !== "string" ||
    !CONNECT_ID.test(created.id) ||
    created.vault?.id !== config.vaultId
  )
    throw new HttpError(502, "invalid_vault_response");
  return { itemId: created.id, vaultId: config.vaultId! };
}

/** Create a single concealed secure-note field and return only its reference. */
export async function createConnectSecret(
  config: ConnectConfig,
  title: string,
  value: string,
): Promise<ConnectSecretReceipt> {
  if (
    typeof title !== "string" ||
    !title.trim() ||
    title.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(title) ||
    typeof value !== "string" ||
    !value.length ||
    value.length > 8192
  )
    throw new HttpError(400, "invalid_secret_save_input");
  // The reference identifier is chosen before dispatch and is independent of the private value.
  // Connect must echo both identifiers; provider controlled identifiers must never enter a receipt.
  const itemId = crypto.randomUUID().replace(/-/g, "").slice(0, 26);
  const fieldId = crypto.randomUUID();
  const created = await connectRequest(config, itemUrl(config), "POST", {
    id: itemId,
    vault: { id: config.vaultId },
    title: title.trim(),
    category: "SECURE_NOTE",
    fields: [{ id: fieldId, label: "Secret", type: "CONCEALED", value }],
  });
  const fields = Array.isArray(created?.fields) ? created.fields : [];
  const matches = fields.filter(
    (field: {
      id?: unknown;
      label?: unknown;
      type?: unknown;
      value?: unknown;
    }) =>
      field?.label === "Secret" &&
      field?.type === "CONCEALED" &&
      field?.value === value &&
      field?.id === fieldId,
  );
  if (
    !created ||
    created.id !== itemId ||
    created.vault?.id !== config.vaultId ||
    matches.length !== 1
  )
    throw new HttpError(502, "invalid_vault_response");
  const reference = `${itemId}#${encodeURIComponent(fieldId)}`;
  if (!(await verifyConnectField(config, reference, value)))
    throw new HttpError(502, "save_outcome_unknown");
  return {
    itemId,
    vaultId: config.vaultId!,
    reference,
    verified: true,
  };
}

export async function replaceConnectItem(
  config: ConnectConfig,
  itemId: string,
  item: Record<string, unknown>,
): Promise<ConnectWriteReceipt> {
  const vault = item.vault;
  if (
    !vault ||
    typeof vault !== "object" ||
    Array.isArray(vault) ||
    (vault as Record<string, unknown>).id !== config.vaultId ||
    item.id !== itemId
  )
    throw new HttpError(400, "connect_item_target_mismatch");
  const updated = await connectRequest(
    config,
    itemUrl(config, itemId),
    "PUT",
    item,
  );
  if (!updated || updated.id !== itemId || updated.vault?.id !== config.vaultId)
    throw new HttpError(502, "invalid_vault_response");
  return { itemId: updated.id, vaultId: config.vaultId! };
}

export async function updateConnectField(
  config: ConnectConfig,
  reference: string,
  value: string,
): Promise<ConnectWriteReceipt> {
  const { itemId, fieldId } = parseConnectReference(reference);
  const updated = await connectRequest(
    config,
    itemUrl(config, itemId),
    "PATCH",
    [
      {
        op: "replace",
        path: `/fields/${jsonPointerSegment(fieldId)}/value`,
        value,
      },
    ],
  );
  if (!updated || updated.id !== itemId || updated.vault?.id !== config.vaultId)
    throw new HttpError(502, "invalid_vault_response");
  return { itemId: updated.id, vaultId: config.vaultId! };
}

/** Update one exact existing field and verify the value with a fresh provider read. */
export async function updateConnectSecret(
  config: ConnectConfig,
  reference: string,
  value: string,
): Promise<ConnectSecretReceipt> {
  if (typeof value !== "string" || !value.length || value.length > 8192)
    throw new HttpError(400, "invalid_secret_save_input");
  const { itemId } = parseConnectReference(reference);
  const updated = await updateConnectField(config, reference, value);
  if (
    updated.itemId !== itemId ||
    !(await verifyConnectField(config, reference, value))
  )
    throw new HttpError(502, "save_outcome_unknown");
  return {
    itemId,
    vaultId: updated.vaultId,
    reference,
    verified: true,
  };
}

/** Remove one exact field without deleting its containing item, then verify absence. */
export async function deleteConnectSecret(
  config: ConnectConfig,
  reference: string,
): Promise<ConnectSecretReceipt> {
  const { itemId, fieldId } = parseConnectReference(reference);
  const updated = await connectRequest(
    config,
    itemUrl(config, itemId),
    "PATCH",
    [{ op: "remove", path: `/fields/${jsonPointerSegment(fieldId)}` }],
  );
  if (!updated || updated.id !== itemId || updated.vault?.id !== config.vaultId)
    throw new HttpError(502, "invalid_vault_response");
  const item = await providerJson(itemUrl(config, itemId), {
    headers: {
      Authorization: "Bearer " + config.accessToken,
      Accept: "application/json",
    },
  });
  if (
    item.id !== itemId ||
    item.vault?.id !== config.vaultId ||
    !Array.isArray(item.fields) ||
    item.fields.some((field: { id?: unknown }) => field?.id === fieldId)
  )
    throw new HttpError(502, "save_outcome_unknown");
  return {
    itemId,
    vaultId: config.vaultId!,
    reference,
    verified: true,
  };
}

export async function deleteConnectItem(
  config: ConnectConfig,
  itemId: string,
): Promise<void> {
  await connectRequest(config, itemUrl(config, itemId), "DELETE");
}

export async function verifyConnectField(
  config: ConnectConfig,
  reference: string,
  expectedValue: string,
): Promise<boolean> {
  return (await resolveConnect(config, reference)) === expectedValue;
}
