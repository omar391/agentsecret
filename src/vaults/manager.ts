import type { Env, SecretPolicy, VaultConfig } from "../types";
import { HttpError } from "../security/primitives";
import { decryptConfig, type Envelope, type VaultBinding } from "./encryption";
import { resolveBitwarden } from "../bitwarden/client";
import { readConnectReference, resolveConnect } from "./onepassword";
import { isSsrfTarget } from "../security/policy";
export function validateVault(input: unknown): VaultConfig {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new HttpError(400, "unsupported_vault_configuration");
  const record = input as Record<string, unknown>;
  const type = record.type;
  const validateKeys = (allowed: readonly string[]) => {
    if (Object.keys(record).some((key) => !allowed.includes(key)))
      throw new HttpError(400, "unsupported_vault_configuration");
  };
  const validId = (value: unknown, max = 128): value is string =>
    typeof value === "string" &&
    new RegExp(`^[A-Za-z0-9_-]{1,${max}}$`).test(value);
  if (type === "bitwarden-password-manager" || type === "lastpass") {
    validateKeys(["type", "profileId"]);
    if (!validId(record.profileId, 80))
      throw new HttpError(400, "invalid_companion_profile");
    return { type, profileId: record.profileId };
  }
  if (type === "onepassword-service-account") {
    validateKeys(["type", "vaultId"]);
    if (!validId(record.vaultId))
      throw new HttpError(400, "onepassword_vault_required");
    return { type, vaultId: record.vaultId };
  }
  if (type !== "bitwarden" && type !== "onepassword-connect")
    throw new HttpError(400, "unsupported_vault_configuration");

  validateKeys(
    type === "bitwarden"
      ? ["type", "accessToken", "apiUrl", "identityUrl"]
      : ["type", "accessToken", "apiUrl", "identityUrl", "vaultId"],
  );
  if (
    typeof record.accessToken !== "string" ||
    record.accessToken.length < 10 ||
    record.accessToken.length > 8192
  )
    throw new HttpError(400, "unsupported_vault_configuration");
  for (const field of ["apiUrl", "identityUrl", "vaultId"] as const) {
    if (Object.hasOwn(record, field) && typeof record[field] !== "string")
      throw new HttpError(400, "unsupported_vault_configuration");
  }

  const config = {
    type,
    accessToken: record.accessToken,
    ...(typeof record.apiUrl === "string" ? { apiUrl: record.apiUrl } : {}),
    ...(typeof record.identityUrl === "string"
      ? { identityUrl: record.identityUrl }
      : {}),
    ...(typeof record.vaultId === "string" ? { vaultId: record.vaultId } : {}),
  } as Extract<VaultConfig, { type: "bitwarden" | "onepassword-connect" }>;

  for (const field of ["apiUrl", "identityUrl"] as const) {
    let url: URL;
    const value = record[field];
    if (typeof value !== "string") continue;
    try {
      url = new URL(value);
    } catch {
      throw new HttpError(400, "invalid_provider_url");
    }
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      isSsrfTarget(url.hostname)
    )
      throw new HttpError(400, "invalid_provider_url");
    if (field === "apiUrl") config.apiUrl = url.toString().replace(/\/$/, "");
    else if (config.type === "bitwarden")
      config.identityUrl = url.toString().replace(/\/$/, "");
  }
  if (
    config.type === "onepassword-connect" &&
    (!config.apiUrl || !validId(config.vaultId))
  )
    throw new HttpError(400, "connect_server_and_vault_required");
  return config;
}
export async function resolveSecret(
  tenant: string,
  policy: SecretPolicy,
  envelope: Envelope | null,
  env: Env,
  connection?: { id: string; revision: number },
): Promise<string> {
  if (tenant !== "default" && !connection)
    throw new HttpError(503, "vault_connection_required");
  if (!envelope) {
    const bound =
      tenant === "default" ? env["SECRET_" + policy.alias] : undefined;
    if (typeof bound === "string" && bound) return bound;
    throw new HttpError(503, "vault_not_connected");
  }
  const binding: VaultBinding | undefined = connection
    ? {
        accountId: tenant,
        connectionId: connection.id,
        revision: connection.revision,
      }
    : undefined;
  const config = validateVault(
    await decryptConfig(envelope, tenant, env, binding),
  );
  if (!policy.secretId)
    throw new HttpError(400, "explicit_secret_reference_required");
  if (
    config.type === "bitwarden-password-manager" ||
    config.type === "onepassword-service-account" ||
    config.type === "lastpass"
  )
    throw new HttpError(503, "secret_store_unavailable");
  return config.type === "bitwarden"
    ? resolveBitwarden(config, policy.secretId)
    : resolveConnect(config, policy.secretId);
}

/** Confirm a direct provider reference without returning its credential value. */
export async function inspectSecretReference(
  config: VaultConfig,
  reference: string,
): Promise<{
  available: true;
  observedValues?: string[];
  title?: string;
  passwordFieldCount?: number;
  selectedFieldPurpose?: unknown;
  selectedFieldId?: string;
  selectedFieldLabel?: unknown;
  category?: unknown;
  username?: string;
  usernameFieldCount?: number;
  itemUris?: string[];
}> {
  if (typeof reference !== "string" || !reference || reference.length > 1024)
    throw new HttpError(400, "invalid_secret_reference");
  if (
    config.type === "bitwarden-password-manager" ||
    config.type === "onepassword-service-account" ||
    config.type === "lastpass"
  )
    throw new HttpError(503, "secret_store_unavailable");
  const inspected =
    config.type === "bitwarden"
      ? { value: await resolveBitwarden(config, reference) }
      : await readConnectReference(config, reference);
  const { value } = inspected;
  if (value.length > 0 && referenceContainsValue(reference, value))
    throw new HttpError(409, "secret_reference_not_safe");
  return {
    available: true,
    ...("observedValues" in inspected
      ? {
          observedValues: inspected.observedValues,
          title: inspected.title,
          passwordFieldCount: inspected.passwordFieldCount,
          selectedFieldPurpose: inspected.selectedFieldPurpose,
          selectedFieldId: inspected.selectedFieldId,
          selectedFieldLabel: inspected.selectedFieldLabel,
          category: inspected.category,
          username: inspected.username,
          usernameFieldCount: inspected.usernameFieldCount,
          itemUris: inspected.itemUris,
        }
      : {}),
  };
}

/** Decode percent-encoded layers before checking whether a ref embeds its value. */
export function referenceContainsValue(
  reference: string,
  value: string,
): boolean {
  let candidate = reference;
  for (let layer = 0; layer <= reference.length; layer++) {
    if (candidate.includes(value)) return true;
    try {
      const decoded = decodeURIComponent(candidate);
      if (decoded === candidate) return false;
      candidate = decoded;
    } catch {
      // A malformed layer can conceal a later decodable copy of the value.
      // Treat it as unsafe rather than allowing the reference to be reflected.
      return true;
    }
  }
  return false;
}
