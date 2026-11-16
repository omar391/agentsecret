import { execFileSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  AccountBoundProviderCredentials,
  type ProviderCredentialBinding,
} from "../provider-credentials";

const ITEM_ID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const FASTFLOW_APP_NAME = /^[A-Za-z0-9_-]{1,80}$/;
const MAX_ITEM_JSON = 1024 * 1024;

function isWellFormed(value: string): boolean {
  try {
    encodeURIComponent(value);
    return true;
  } catch {
    return false;
  }
}

interface BitwardenField {
  name?: unknown;
  value?: unknown;
  type?: unknown;
}

interface BitwardenItem {
  id?: unknown;
  name?: unknown;
  type?: unknown;
  fields?: unknown;
  login?: unknown;
  notes?: unknown;
  favorite?: unknown;
  reprompt?: unknown;
}

export interface BitwardenPasswordManagerRunner {
  ensureSession(appName: string): Promise<FastflowBitwardenProfileIdentity>;
  readItem(appName: string, itemId: string): Promise<string>;
  createItem(appName: string, encodedItem: string): Promise<string>;
  editItem(appName: string, itemId: string, encodedItem: string): Promise<string>;
}

export interface BitwardenPasswordManagerSafeReceipt {
  status: "created" | "updated" | "unchanged";
  reference: string;
  verified: true;
}

export interface FastflowBitwardenProfileIdentity {
  userId: string;
  userEmail: string;
  serverUrl: string;
}

interface FastflowBitwardenProfileBinding extends FastflowBitwardenProfileIdentity {
  schema: "agentsecret/fastflow-bitwarden-profile/v1";
  appName: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function parseProfileBinding(value: string): FastflowBitwardenProfileBinding {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("bitwarden_password_manager_profile_unconfigured");
  }
  if (
    !isRecord(parsed) ||
    Object.keys(parsed).sort().join(",") !==
      "appName,schema,serverUrl,userEmail,userId" ||
    parsed.schema !== "agentsecret/fastflow-bitwarden-profile/v1" ||
    typeof parsed.appName !== "string" ||
    !FASTFLOW_APP_NAME.test(parsed.appName) ||
    typeof parsed.userId !== "string" ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(parsed.userId) ||
    typeof parsed.userEmail !== "string" ||
    !/^[^\s@]{1,128}@[^\s@]{1,253}$/.test(parsed.userEmail) ||
    typeof parsed.serverUrl !== "string"
  )
    throw new Error("bitwarden_password_manager_profile_unconfigured");
  let server: URL;
  try {
    server = new URL(parsed.serverUrl);
  } catch {
    throw new Error("bitwarden_password_manager_profile_unconfigured");
  }
  if (
    server.protocol !== "https:" ||
    server.username ||
    server.password ||
    server.pathname !== "/" ||
    server.search ||
    server.hash ||
    server.origin !== parsed.serverUrl.replace(/\/$/, "")
  )
    throw new Error("bitwarden_password_manager_profile_unconfigured");
  return parsed as unknown as FastflowBitwardenProfileBinding;
}

function encodeFieldName(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function decodeFieldName(value: string): string | null {
  try {
    const decoded = decodeURIComponent(value);
    if (
      !decoded ||
      !isWellFormed(decoded) ||
      /[\u0000-\u001f\u007f]/.test(decoded) ||
      encodeFieldName(decoded) !== value
    )
      return null;
    return decoded;
  } catch {
    return null;
  }
}

function parseReference(reference: string): {
  itemId: string;
  field: "password" | "username" | "totp" | { customName: string };
} {
  if (
    typeof reference !== "string" ||
    reference.length > 1024 ||
    /[\u0000-\u001f\u007f]/.test(reference)
  )
    throw new Error("bitwarden_password_manager_reference_invalid");
  const separator = reference.indexOf("#");
  if (separator <= 0 || separator !== reference.lastIndexOf("#"))
    throw new Error("bitwarden_password_manager_reference_invalid");
  const itemId = reference.slice(0, separator);
  const fieldPath = reference.slice(separator + 1);
  if (!ITEM_ID.test(itemId) || itemId !== itemId.toLowerCase())
    throw new Error("bitwarden_password_manager_reference_invalid");
  if (fieldPath === "/login/password") return { itemId, field: "password" };
  if (fieldPath === "/login/username") return { itemId, field: "username" };
  if (fieldPath === "/login/totp") return { itemId, field: "totp" };
  const customPrefix = "/fields/";
  if (fieldPath.startsWith(customPrefix)) {
    const customName = decodeFieldName(fieldPath.slice(customPrefix.length));
    if (customName) return { itemId, field: { customName } };
  }
  throw new Error("bitwarden_password_manager_reference_invalid");
}

type BitwardenFieldTarget = ReturnType<typeof parseReference>["field"];

function parseItem(json: string, expectedId: string): BitwardenItem {
  if (
    typeof json !== "string" ||
    Buffer.byteLength(json, "utf8") > MAX_ITEM_JSON
  )
    throw new Error("bitwarden_password_manager_item_invalid");
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("bitwarden_password_manager_item_invalid");
  }
  if (!isRecord(parsed) || parsed.type !== 1 || !isRecord(parsed.login))
    throw new Error("bitwarden_password_manager_item_invalid");
  if (expectedId && parsed.id !== expectedId)
    throw new Error("bitwarden_password_manager_item_invalid");
  return parsed as BitwardenItem;
}

function exactFieldValue(
  item: BitwardenItem,
  field: ReturnType<typeof parseReference>["field"],
): string {
  const login = isRecord(item.login) ? item.login : {};
  if (field === "password" || field === "username" || field === "totp") {
    const key =
      field === "password"
        ? "password"
        : field === "username"
          ? "username"
          : "totp";
    const value = login[key];
    if (typeof value !== "string" || !value)
      throw new Error("bitwarden_password_manager_field_unavailable");
    return value;
  }
  if (!Array.isArray(item.fields))
    throw new Error("bitwarden_password_manager_field_unavailable");
  const matches = item.fields.filter(
    (candidate): candidate is BitwardenField =>
      isRecord(candidate) && candidate.name === field.customName,
  );
  if (
    matches.length !== 1 ||
    typeof matches[0]?.value !== "string" ||
    !matches[0].value
  )
    throw new Error("bitwarden_password_manager_field_unavailable");
  return matches[0].value;
}

function fieldPath(field: BitwardenFieldTarget): string {
  return field === "password" || field === "username" || field === "totp"
    ? "/login/" + field
    : bitwardenPasswordManagerCustomFieldPath(field.customName);
}

function assertWritableValue(value: string): void {
  if (
    typeof value !== "string" ||
    !value ||
    Buffer.byteLength(value, "utf8") > 8192 ||
    !isWellFormed(value)
  )
    throw new Error("bitwarden_password_manager_update_invalid");
}

function normalizeCustomFields(fields: unknown): Array<{
  name: unknown;
  value: unknown;
  type?: unknown;
}> {
  if (!Array.isArray(fields)) return [];
  return fields
    .filter((field): field is BitwardenField => isRecord(field))
    .map((field) => ({
      name: field.name,
      value: field.value,
      type: field.type,
    }))
    .sort((a, b) => String(a.name).localeCompare(String(b.name)));
}

function normalizeLogin(login: unknown): Record<string, unknown> {
  if (!isRecord(login)) return {};
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(login).sort()) result[key] = login[key];
  return result;
}

function sameSiblingFields(
  before: BitwardenItem,
  after: BitwardenItem,
  updatedField: BitwardenFieldTarget,
): boolean {
  const without = (item: BitwardenItem) => {
    const login = normalizeLogin(item.login);
    if (typeof updatedField === "string") delete login[updatedField];
    const fields = normalizeCustomFields(item.fields).filter(
      (field) =>
        typeof updatedField !== "object" || field.name !== updatedField.customName,
    );
    return JSON.stringify({ login, fields });
  };
  return without(before) === without(after);
}

function setFieldValue(
  item: BitwardenItem,
  field: BitwardenFieldTarget,
  value: string,
): BitwardenItem {
  const next = structuredClone(item) as BitwardenItem & Record<string, unknown>;
  if (typeof field === "string") {
    const login = isRecord(next.login) ? { ...next.login } : {};
    login[field] = value;
    next.login = login;
    return next;
  }
  const fields = Array.isArray(next.fields) ? [...next.fields] : [];
  const matches = fields.filter(
    (candidate): candidate is BitwardenField =>
      isRecord(candidate) && candidate.name === field.customName,
  );
  if (matches.length !== 1)
    throw new Error("bitwarden_password_manager_field_unavailable");
  next.fields = fields.map((candidate) =>
    isRecord(candidate) && candidate.name === field.customName
      ? { ...candidate, value }
      : candidate,
  );
  return next;
}

function encodeItem(item: BitwardenItem): string {
  return Buffer.from(JSON.stringify(item), "utf8").toString("base64");
}

/**
 * Read exact fields from a separately enrolled Fastflow `bw` profile. Decrypted
 * item JSON and field values remain in this process; callers receive only the
 * result of a trusted callback. The account-bound Keychain record stores the
 * Fastflow app name, never a master password or Bitwarden session value.
 */
export class BitwardenPasswordManagerAdapter {
  constructor(
    private readonly binding: ProviderCredentialBinding,
    private readonly credentials: AccountBoundProviderCredentials,
    private readonly runner: BitwardenPasswordManagerRunner = fastflowBwRunner,
  ) {
    if (binding.providerMode !== "bitwarden-password-manager")
      throw new Error("bitwarden_password_manager_binding_invalid");
  }

  async withResolvedField<T>(
    reference: string,
    consume: (value: string) => Promise<T>,
  ): Promise<T> {
    const { itemId, field } = parseReference(reference);
    const profile = await this.profile();
    try {
      const identity = await this.runner.ensureSession(profile.appName);
      if (
        identity.userId !== profile.userId ||
        identity.userEmail.toLowerCase() !== profile.userEmail.toLowerCase() ||
        identity.serverUrl.replace(/\/$/, "") !==
          profile.serverUrl.replace(/\/$/, "")
      )
        throw new Error("bitwarden_password_manager_profile_mismatch");
      const raw = await this.runner.readItem(profile.appName, itemId);
      const item = parseItem(raw, itemId);
      return await consume(exactFieldValue(item, field));
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.startsWith("bitwarden_password_manager_")
      )
        throw error;
      throw new Error("bitwarden_password_manager_read_failed");
    }
  }

  private async profile(): Promise<FastflowBitwardenProfileBinding> {
    const storedProfile = await this.credentials.get(this.binding);
    if (!storedProfile)
      throw new Error("bitwarden_password_manager_profile_unconfigured");
    return parseProfileBinding(storedProfile);
  }

  private async ensureProfileSession(
    profile: FastflowBitwardenProfileBinding,
  ): Promise<void> {
    const identity = await this.runner.ensureSession(profile.appName);
    if (
      identity.userId !== profile.userId ||
      identity.userEmail.toLowerCase() !== profile.userEmail.toLowerCase() ||
      identity.serverUrl.replace(/\/$/, "") !==
        profile.serverUrl.replace(/\/$/, "")
    )
      throw new Error("bitwarden_password_manager_profile_mismatch");
  }

  private async readItem(
    profile: FastflowBitwardenProfileBinding,
    itemId: string,
  ): Promise<BitwardenItem> {
    return parseItem(
      await this.runner.readItem(profile.appName, itemId),
      itemId,
    );
  }

  /**
   * Protected create/update/ensure through the bound Fastflow bw profile.
   * The whole item is base64-encoded on stdin; sibling fields survive a
   * read-modify-replace and a fresh read-back verifies the exact field.
   * Outcome-unknown errors let the broker ticket reconcile before retrying.
   */
  async createSecret(
    title: string,
    value: string,
  ): Promise<BitwardenPasswordManagerSafeReceipt> {
    const normalTitle = title.trim();
    if (
      typeof title !== "string" ||
      title !== normalTitle ||
      !normalTitle ||
      normalTitle.length > 128 ||
      /[\\/#\u0000-\u001f\u007f]/.test(normalTitle) ||
      !isWellFormed(normalTitle)
    )
      throw new Error("bitwarden_password_manager_create_invalid");
    assertWritableValue(value);
    const profile = await this.profile();
    await this.ensureProfileSession(profile);
    const encoded = encodeItem({
      type: 1,
      name: normalTitle,
      login: { uris: [], username: "", password: value, totp: null },
      fields: [],
      notes: "",
      favorite: false,
      reprompt: 0,
    });
    let createdId: string;
    try {
      const output = await this.runner.createItem(profile.appName, encoded);
      const created = parseItem(output, "");
      if (typeof created.id !== "string" || !ITEM_ID.test(created.id) || !isRecord(created.login))
        throw new Error("unexpected identity");
      createdId = created.id;
    } catch {
      throw new Error("bitwarden_password_manager_create_outcome_unknown");
    }
    const reference = bitwardenPasswordManagerReference(
      createdId,
      "/login/password",
    );
    try {
      const observed = await this.readItem(profile, createdId);
      if (
        exactFieldValue(observed, "password") !== value ||
        observed.name !== normalTitle
      )
        throw new Error("verification mismatch");
      return { status: "created", reference, verified: true };
    } catch {
      throw new Error("bitwarden_password_manager_create_outcome_unknown");
    }
  }

  async updateField(
    reference: string,
    value: string,
  ): Promise<BitwardenPasswordManagerSafeReceipt> {
    assertWritableValue(value);
    const { itemId, field } = parseReference(reference);
    const profile = await this.profile();
    await this.ensureProfileSession(profile);
    const before = await this.readItem(profile, itemId);
    const next = setFieldValue(before, field, value);
    const encoded = encodeItem(next);
    try {
      const output = await this.runner.editItem(
        profile.appName,
        itemId,
        encoded,
      );
      const observed = parseItem(output, itemId);
      if (
        exactFieldValue(observed, field) !== value ||
        !sameSiblingFields(before, observed, field)
      )
        throw new Error("verification mismatch");
    } catch {
      throw new Error("bitwarden_password_manager_update_outcome_unknown");
    }
    try {
      const readback = await this.readItem(profile, itemId);
      if (
        exactFieldValue(readback, field) !== value ||
        !sameSiblingFields(before, readback, field)
      )
        throw new Error("verification mismatch");
    } catch {
      throw new Error("bitwarden_password_manager_update_outcome_unknown");
    }
    return {
      status: "updated",
      reference: bitwardenPasswordManagerReference(itemId, fieldPath(field)),
      verified: true,
    };
  }

  async ensureField(
    reference: string,
    value: string,
  ): Promise<BitwardenPasswordManagerSafeReceipt> {
    assertWritableValue(value);
    let current = "";
    await this.withResolvedField(reference, async (observed) => {
      current = observed;
    });
    if (current === value)
      return { status: "unchanged", reference, verified: true };
    const updated = await this.updateField(reference, value);
    return { ...updated, status: "updated" };
  }
}

const FASTFLOW_BIN = join(homedir(), ".local", "bin", "fastflow");
const FASTFLOW_BW_BIN = join(homedir(), ".local", "bin", "fastflow-bw");

function fastflowEnvironment(appName: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    FASTFLOW_APP_NAME: appName,
  };
}

function runFastflow(
  executable: string,
  args: string[],
  appName: string,
  input?: string,
): string {
  try {
    return execFileSync(executable, args, {
      encoding: "utf8",
      env: fastflowEnvironment(appName),
      input,
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 60_000,
      maxBuffer: MAX_ITEM_JSON,
    });
  } catch {
    throw new Error("bitwarden_password_manager_command_failed");
  }
}

const fastflowBwRunner: BitwardenPasswordManagerRunner = {
  async ensureSession(appName) {
    const output = runFastflow(
      FASTFLOW_BIN,
      ["secrets", "session", "ensure", "--store", "bitwarden-cli"],
      appName,
    );
    let response: unknown;
    try {
      response = JSON.parse(output);
    } catch {
      throw new Error("bitwarden_password_manager_session_unavailable");
    }
    const result = isRecord(response) ? response.result : undefined;
    const secretStore = isRecord(result) ? result.secretStore : undefined;
    if (!isRecord(secretStore) || secretStore.cliState !== "unlocked")
      throw new Error("bitwarden_password_manager_session_unavailable");
    const statusOutput = runFastflow(
      FASTFLOW_BW_BIN,
      ["--raw", "status"],
      appName,
    );
    let status: unknown;
    try {
      status = JSON.parse(statusOutput);
    } catch {
      throw new Error("bitwarden_password_manager_session_unavailable");
    }
    if (
      !isRecord(status) ||
      status.status !== "unlocked" ||
      typeof status.userId !== "string" ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(status.userId) ||
      typeof status.userEmail !== "string" ||
      !/^[^\s@]{1,128}@[^\s@]{1,253}$/.test(status.userEmail) ||
      typeof status.serverUrl !== "string"
    )
      throw new Error("bitwarden_password_manager_session_unavailable");
    let server: URL;
    try {
      server = new URL(status.serverUrl);
    } catch {
      throw new Error("bitwarden_password_manager_session_unavailable");
    }
    if (
      server.protocol !== "https:" ||
      server.username ||
      server.password ||
      server.pathname !== "/" ||
      server.search ||
      server.hash
    )
      throw new Error("bitwarden_password_manager_session_unavailable");
    return {
      userId: status.userId,
      userEmail: status.userEmail,
      serverUrl: server.origin,
    };
  },
  async readItem(appName, itemId) {
    return runFastflow(
      FASTFLOW_BW_BIN,
      ["--raw", "get", "item", itemId],
      appName,
    );
  },
  async createItem(appName, encodedItem) {
    return runFastflow(
      FASTFLOW_BW_BIN,
      ["--raw", "create", "item"],
      appName,
      encodedItem,
    );
  },
  async editItem(appName, itemId, encodedItem) {
    return runFastflow(
      FASTFLOW_BW_BIN,
      ["--raw", "edit", "item", itemId],
      appName,
      encodedItem,
    );
  },
};

/** Ensure a Fastflow profile is unlocked and return its non-secret account identity. */
export async function inspectFastflowBitwardenProfile(
  appName: string,
): Promise<FastflowBitwardenProfileIdentity> {
  if (!FASTFLOW_APP_NAME.test(appName))
    throw new Error("bitwarden_password_manager_profile_invalid");
  try {
    return await fastflowBwRunner.ensureSession(appName);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith("bitwarden_password_manager_")
    )
      throw error;
    throw new Error("bitwarden_password_manager_session_unavailable");
  }
}

export function serializeFastflowBitwardenProfile(
  appName: string,
  identity: FastflowBitwardenProfileIdentity,
): string {
  if (
    !FASTFLOW_APP_NAME.test(appName) ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(identity.userId) ||
    !/^[^\s@]{1,128}@[^\s@]{1,253}$/.test(identity.userEmail)
  )
    throw new Error("bitwarden_password_manager_profile_invalid");
  let server: URL;
  try {
    server = new URL(identity.serverUrl);
  } catch {
    throw new Error("bitwarden_password_manager_profile_invalid");
  }
  if (
    server.protocol !== "https:" ||
    server.username ||
    server.password ||
    server.pathname !== "/" ||
    server.search ||
    server.hash
  )
    throw new Error("bitwarden_password_manager_profile_invalid");
  return JSON.stringify({
    schema: "agentsecret/fastflow-bitwarden-profile/v1",
    appName,
    userId: identity.userId,
    userEmail: identity.userEmail,
    serverUrl: server.origin,
  } satisfies FastflowBitwardenProfileBinding);
}

export function bitwardenPasswordManagerReference(
  itemId: string,
  fieldPath: string,
): string {
  const reference = `${itemId}#${fieldPath}`;
  parseReference(reference);
  return reference;
}

export function bitwardenPasswordManagerCustomFieldPath(name: string): string {
  if (
    typeof name !== "string" ||
    !name ||
    !isWellFormed(name) ||
    /[\u0000-\u001f\u007f]/.test(name)
  )
    throw new Error("bitwarden_password_manager_reference_invalid");
  const path = `/fields/${encodeFieldName(name)}`;
  if (!decodeFieldName(path.slice("/fields/".length)))
    throw new Error("bitwarden_password_manager_reference_invalid");
  return path;
}
