import type { ConnectLoginFindSelector, VaultConfig } from "../types";
import { HttpError } from "../security/primitives";
import { providerCapabilities } from "./capabilities";
import { inspectSecretReference, referenceContainsValue } from "./manager";
import {
  createConnectSecret,
  deleteConnectSecret,
  findConnectReferenceByTitle,
  updateConnectSecret,
} from "./onepassword";

export type SecretWriteIntent = "create" | "update" | "delete";

export interface SecretWriteReceipt {
  reference: string;
  verified: true;
}

export interface SecretFindReceipt {
  status: "available";
  provider: VaultConfig["type"];
  reference: string;
}

function isCompanionProvider(config: VaultConfig): config is Extract<
  VaultConfig,
  {
    type:
      "bitwarden-password-manager" | "onepassword-service-account" | "lastpass";
  }
> {
  return (
    config.type === "bitwarden-password-manager" ||
    config.type === "onepassword-service-account" ||
    config.type === "lastpass"
  );
}

interface SecretFindSelectorCheck {
  title: string;
  requireUniquePasswordField: boolean;
  loginSelector?: ConnectLoginFindSelector;
}

/** Shared provider mutation boundary used after each interface's own authorization/admission. */
export async function writeSecret(
  config: VaultConfig,
  intent: SecretWriteIntent,
  target: string,
  value?: string,
): Promise<SecretWriteReceipt> {
  if (config.type !== "onepassword-connect")
    throw new HttpError(409, "provider_write_unsupported");
  if (intent !== "delete" && typeof value !== "string")
    throw new HttpError(400, "invalid_secret_save_input");
  const receipt =
    intent === "delete"
      ? await deleteConnectSecret(config, target)
      : intent === "create"
        ? await createConnectSecret(config, target, value!)
        : await updateConnectSecret(config, target, value!);
  if (!receipt.verified || !receipt.reference)
    throw new HttpError(502, "save_outcome_unknown");
  return { reference: receipt.reference, verified: true };
}

/** Shared, reference-only find operation for customer and agent interfaces. */
export async function findSecretByReference(
  config: VaultConfig,
  reference: string,
  observedValues: string[] = [],
  selector?: SecretFindSelectorCheck,
): Promise<SecretFindReceipt> {
  if (isCompanionProvider(config))
    throw new HttpError(503, "secret_store_unavailable");
  if (config.type !== "bitwarden" && config.type !== "onepassword-connect")
    throw new HttpError(409, "provider_read_unsupported");
  const mode =
    config.type === "bitwarden"
      ? "bitwarden-secrets-manager"
      : "onepassword-connect";
  if (!providerCapabilities(mode).read)
    throw new HttpError(409, "provider_read_unsupported");
  if (
    observedValues.some(
      (value) => value.length > 0 && referenceContainsValue(reference, value),
    )
  )
    throw new HttpError(409, "secret_reference_not_safe");
  const inspected = await inspectSecretReference(config, reference);
  if (selector && inspected.title !== selector.title)
    throw new HttpError(409, "secret_selector_changed");
  if (
    selector?.requireUniquePasswordField &&
    (inspected.passwordFieldCount !== 1 ||
      inspected.selectedFieldPurpose !== "PASSWORD")
  )
    throw new HttpError(409, "secret_selector_changed");
  if (
    selector?.loginSelector &&
    (inspected.category !== "LOGIN" ||
      inspected.usernameFieldCount !== 1 ||
      inspected.username !== selector.loginSelector.username ||
      inspected.selectedFieldId !== selector.loginSelector.fieldId ||
      inspected.selectedFieldPurpose !== "PASSWORD" ||
      (selector.loginSelector.fieldPath !== undefined &&
        inspected.selectedFieldLabel !== selector.loginSelector.fieldPath) ||
      !inspected.itemUris ||
      inspected.itemUris.length !== selector.loginSelector.uris.length ||
      !selector.loginSelector.uris.every((uri) =>
        inspected.itemUris!.includes(uri),
      ))
  )
    throw new HttpError(409, "secret_selector_changed");
  if (
    inspected.observedValues?.some(
      (value) => value.length > 0 && referenceContainsValue(reference, value),
    )
  )
    throw new HttpError(409, "secret_reference_not_safe");
  return {
    status: "available",
    provider: config.type,
    reference,
  };
}

/** Connect title lookup is exact, bounded to one selected connection, and ref-only. */
export async function findSecretByTitle(
  config: VaultConfig,
  title: string,
  fieldId?: string,
): Promise<SecretFindReceipt> {
  if (isCompanionProvider(config))
    throw new HttpError(503, "secret_store_unavailable");
  if (config.type !== "onepassword-connect")
    throw new HttpError(409, "provider_selector_unsupported");
  const selected = await findConnectReferenceByTitle(config, title, fieldId);
  return findSecretByReference(
    config,
    selected.reference,
    selected.observedValues,
    {
      title: selected.title,
      requireUniquePasswordField: fieldId === undefined,
    },
  );
}

/** Resolve an owner-pinned login locator without searching by username or URL. */
export async function findSecretByLoginSelector(
  config: VaultConfig,
  selector: ConnectLoginFindSelector,
): Promise<SecretFindReceipt> {
  if (isCompanionProvider(config))
    throw new HttpError(503, "secret_store_unavailable");
  if (config.type !== "onepassword-connect")
    throw new HttpError(409, "provider_selector_unsupported");
  const selected = await findConnectReferenceByTitle(
    config,
    selector.title,
    selector.fieldId,
    selector,
  );
  return findSecretByReference(
    config,
    selected.reference,
    selected.observedValues,
    {
      title: selector.title,
      requireUniquePasswordField: false,
      loginSelector: selector,
    },
  );
}
