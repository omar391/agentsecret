import {
  connectReferenceFromGeneric,
  hasUnsafeConnectReferenceCharacter,
} from "../src/security/primitives";

export type NormalizedSecretRefBinding = {
  store: string;
  objectId: string;
  fieldPath: string | null;
  reference?: string;
};

const STORES = new Set([
  "bitwarden-cli",
  "bitwarden-secrets-manager",
  "onepassword-connect",
  "onepassword-service-account",
  "lastpass",
]);

/**
 * Stores whose provider mode is companion-gated: no cloud adapter exists, so
 * a locator naming one must fail as `secret_store_unavailable` before any
 * authority, quota, or provider access — never as a generic invalid request.
 */
export const COMPANION_ONLY_STORES = new Set([
  "bitwarden-cli",
  "onepassword-service-account",
  "lastpass",
]);

/**
 * Stores with a cloud adapter, but no name/login locator mapping: a locator
 * naming one must fail as `secret_binding_unsupported` (not `unavailable`)
 * before authority, quota, or provider access.
 */
export const LOCATOR_UNSUPPORTED_STORES = new Set([
  "bitwarden-secrets-manager",
]);

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/** Parse the audited direct `{ secret_ref: ... }` consumer binding shape. */
export function normalizeSecretRefBinding(
  input: unknown,
): NormalizedSecretRefBinding | null {
  if (
    !record(input) ||
    Object.keys(input).length !== 1 ||
    !record(input.secret_ref)
  )
    return null;

  const ref = input.secret_ref;
  const allowed = new Set([
    "type",
    "store",
    "object_id",
    "objectId",
    "field_path",
    "fieldPath",
  ]);
  if (
    Object.keys(ref).some((key) => !allowed.has(key)) ||
    (ref.type !== undefined &&
      ref.type !== "secret_ref" &&
      ref.type !== "secret-ref") ||
    ("object_id" in ref && "objectId" in ref) ||
    ("field_path" in ref && "fieldPath" in ref)
  )
    return null;

  const store =
    ref.store === undefined
      ? "bitwarden-cli"
      : typeof ref.store === "string"
        ? ref.store.trim()
        : "";
  const objectValue = ref.object_id ?? ref.objectId;
  const rawObjectId = typeof objectValue === "string" ? objectValue : "";
  const objectId =
    store === "onepassword-connect" ? rawObjectId : rawObjectId.trim();
  const fieldValue = ref.field_path ?? ref.fieldPath;
  if (
    fieldValue !== undefined &&
    fieldValue !== null &&
    typeof fieldValue !== "string"
  )
    return null;
  const fieldPath: string | null = fieldValue == null ? null : fieldValue;
  const reference =
    store === "onepassword-connect"
      ? connectReferenceFromGeneric(objectId, fieldPath)
      : undefined;
  if (store === "onepassword-connect" && !reference) return null;
  if (
    !STORES.has(store) ||
    !objectId ||
    objectId.length > 1024 ||
    /[\u0000-\u001f\u007f]/.test(objectId) ||
    hasUnsafeConnectReferenceCharacter(objectId) ||
    (store !== "onepassword-connect" &&
      fieldPath !== null &&
      (typeof fieldPath !== "string" ||
        fieldPath.length > 1024 ||
        /[\u0000-\u001f\u007f]/.test(fieldPath) ||
        hasUnsafeConnectReferenceCharacter(fieldPath) ||
        (fieldPath !== "" && !fieldPath.startsWith("/"))))
  )
    return null;

  return {
    store,
    objectId,
    fieldPath,
    ...(reference ? { reference } : {}),
  };
}

/** Resolve the audited named input form without accepting or forwarding other workflow inputs. */
export function normalizeSecretRefInputBinding(
  binding: unknown,
  inputs: unknown,
): NormalizedSecretRefBinding | null {
  if (
    !record(binding) ||
    Object.keys(binding).length !== 1 ||
    !Object.hasOwn(binding, "secret_ref_input")
  )
    return null;

  const inputBinding = binding.secret_ref_input;
  let inputName: string;
  let fieldPathOverride: string | undefined;
  if (typeof inputBinding === "string") {
    inputName = inputBinding.trim();
  } else if (record(inputBinding)) {
    if (
      Object.keys(inputBinding).some(
        (key) => key !== "name" && key !== "field_path",
      ) ||
      typeof inputBinding.name !== "string" ||
      (inputBinding.field_path !== undefined &&
        typeof inputBinding.field_path !== "string")
    )
      return null;
    inputName = inputBinding.name.trim();
    fieldPathOverride = inputBinding.field_path as string | undefined;
  } else {
    return null;
  }

  if (
    !inputName ||
    inputName.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(inputName) ||
    hasUnsafeConnectReferenceCharacter(inputName) ||
    (fieldPathOverride !== undefined &&
      (fieldPathOverride.length > 1024 ||
        /[\u0000-\u001f\u007f]/.test(fieldPathOverride) ||
        hasUnsafeConnectReferenceCharacter(fieldPathOverride) ||
        (fieldPathOverride !== "" && !fieldPathOverride.startsWith("/")))) ||
    !record(inputs) ||
    Object.keys(inputs).length !== 1 ||
    !Object.hasOwn(inputs, inputName)
  )
    return null;

  const inputRef = inputs[inputName];
  if (
    !record(inputRef) ||
    (inputRef.type !== "secret_ref" && inputRef.type !== "secret-ref")
  )
    return null;
  // For Connect, select the effective field path first: a valid override may supply
  // the path when the embedded ref omits it. Bypass the inner normalizer's
  // immediate reference check by resolving the embedded binding here.
  const normalized = normalizeSecretRefBinding({ secret_ref: inputRef });
  let store: string;
  let objectId: string;
  let embeddedFieldPath: string | null;
  if (normalized) {
    store = normalized.store;
    objectId = normalized.objectId;
    embeddedFieldPath = normalized.fieldPath;
  } else {
    // Null from the inner normalizer may be solely a missing/invalid embedded
    // field path for Connect when an override exists. Re-derive the embedded
    // shape directly so a valid override is not masked by the inner check.
    const ref = inputRef as Record<string, unknown>;
    const allowedFallback = new Set([
      "type",
      "store",
      "object_id",
      "objectId",
      "field_path",
      "fieldPath",
    ]);
    if (
      Object.keys(ref).some((k) => !allowedFallback.has(k)) ||
      (ref.type !== undefined &&
        ref.type !== "secret_ref" &&
        ref.type !== "secret-ref") ||
      ("object_id" in ref && "objectId" in ref) ||
      ("field_path" in ref && "fieldPath" in ref) ||
      typeof ref.store !== "string"
    ) {
      return null;
    }
    const s = ref.store.trim();
    if (s !== "onepassword-connect") return null;
    if (fieldPathOverride === undefined) return null;
    const objVal = ref.object_id ?? ref.objectId;
    if (typeof objVal !== "string") return null;
    objectId = objVal;
    store = s;
    const fv = ref.field_path ?? ref.fieldPath;
    if (fv !== undefined && fv !== null && typeof fv !== "string") {
      return null;
    }
    if (
      typeof fv === "string" &&
      fv !== "" &&
      !connectReferenceFromGeneric(objVal, fv)
    ) {
      // A malformed embedded field path is tolerated only when an explicit
      // field_path override supplies the effective Connect field below;
      // without a valid override the reference check further down still fails.
      if (fieldPathOverride === undefined) return null;
    }
    embeddedFieldPath = fv == null ? null : fv;
  }
  const fieldPath = fieldPathOverride ?? embeddedFieldPath;
  const reference =
    store === "onepassword-connect"
      ? connectReferenceFromGeneric(objectId, fieldPath)
      : undefined;
  if (store === "onepassword-connect" && !reference) return null;
  const connectReference = reference as string | undefined;
  return {
    store,
    objectId,
    fieldPath,
    ...(store === "onepassword-connect" ? { reference: connectReference } : {}),
  };
}

export type NormalizedNamedSecretLocator = {
  store: string;
  name: string;
  fieldPath: string | null;
};

/** Parse only the audited named_secret locator; other locator kinds need distinct adapters. */
export function normalizeNamedSecretLocatorBinding(
  binding: unknown,
): NormalizedNamedSecretLocator | null {
  if (
    !record(binding) ||
    Object.keys(binding).length !== 1 ||
    !record(binding.secret_locator)
  )
    return null;
  const locator = binding.secret_locator;
  if (
    Object.keys(locator).some(
      (key) =>
        !["kind", "store", "name", "field_path", "fieldPath"].includes(key),
    ) ||
    locator.kind !== "named_secret" ||
    ("field_path" in locator && "fieldPath" in locator)
  )
    return null;

  const store =
    locator.store === undefined
      ? "bitwarden-cli"
      : typeof locator.store === "string"
        ? locator.store.trim()
        : "";
  const name = typeof locator.name === "string" ? locator.name.trim() : "";
  const fieldValue = locator.field_path ?? locator.fieldPath;
  const fieldPath = fieldValue == null ? null : fieldValue;
  if (
    !STORES.has(store) ||
    !name ||
    name.length > 128 ||
    hasUnsafeConnectReferenceCharacter(name) ||
    /[\u0000-\u001f\u007f]/.test(name) ||
    (fieldPath !== null &&
      (typeof fieldPath !== "string" ||
        fieldPath.length > 1024 ||
        /[\u0000-\u001f\u007f]/.test(fieldPath) ||
        hasUnsafeConnectReferenceCharacter(fieldPath) ||
        (fieldPath !== "" && !fieldPath.startsWith("/"))))
  )
    return null;
  return { store, name, fieldPath };
}

/** Resolve only a single named input containing the audited named_secret locator. */
export function normalizeNamedSecretLocatorInputBinding(
  binding: unknown,
  inputs: unknown,
): NormalizedNamedSecretLocator | null {
  if (
    !record(binding) ||
    Object.keys(binding).length !== 1 ||
    !Object.hasOwn(binding, "secret_locator_input")
  )
    return null;

  const inputBinding = binding.secret_locator_input;
  const inputName =
    typeof inputBinding === "string"
      ? inputBinding.trim()
      : record(inputBinding) &&
          Object.keys(inputBinding).length === 1 &&
          typeof inputBinding.name === "string"
        ? inputBinding.name.trim()
        : "";
  if (
    !inputName ||
    inputName.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(inputName) ||
    hasUnsafeConnectReferenceCharacter(inputName) ||
    !record(inputs) ||
    Object.keys(inputs).length !== 1 ||
    !Object.hasOwn(inputs, inputName)
  )
    return null;
  return normalizeNamedSecretLocatorBinding({
    secret_locator: inputs[inputName],
  });
}

export type NormalizedLoginLookupLocator = {
  store: string;
  username: string;
  uris: string[];
  fieldPath: string | null;
};

/** Parse the audited login_lookup locator without adding a consumer-supplied title or field ID. */
export function normalizeLoginLookupLocatorBinding(
  binding: unknown,
): NormalizedLoginLookupLocator | null {
  if (
    !record(binding) ||
    Object.keys(binding).length !== 1 ||
    !record(binding.secret_locator)
  )
    return null;
  const locator = binding.secret_locator;
  if (
    Object.keys(locator).some(
      (key) =>
        ![
          "kind",
          "store",
          "username",
          "uris",
          "field_path",
          "fieldPath",
        ].includes(key),
    ) ||
    locator.kind !== "login_lookup" ||
    ("field_path" in locator && "fieldPath" in locator)
  )
    return null;

  const store =
    locator.store === undefined
      ? "bitwarden-cli"
      : typeof locator.store === "string"
        ? locator.store.trim()
        : "";
  const username =
    typeof locator.username === "string" ? locator.username.trim() : "";
  const fieldValue = locator.field_path ?? locator.fieldPath;
  const fieldPath = fieldValue == null ? null : fieldValue;
  const uris = Array.isArray(locator.uris)
    ? locator.uris.map((uri) => (typeof uri === "string" ? uri.trim() : ""))
    : [];
  if (
    !STORES.has(store) ||
    !username ||
    username.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(username) ||
    hasUnsafeConnectReferenceCharacter(username) ||
    uris.length < 1 ||
    uris.length > 16 ||
    uris.some(
      (uri) =>
        !uri ||
        uri.length > 2048 ||
        /[\u0000-\u001f\u007f]/.test(uri) ||
        hasUnsafeConnectReferenceCharacter(uri),
    ) ||
    new Set(uris).size !== uris.length ||
    (fieldPath !== null &&
      (typeof fieldPath !== "string" ||
        fieldPath.length > 1024 ||
        /[\u0000-\u001f\u007f]/.test(fieldPath) ||
        hasUnsafeConnectReferenceCharacter(fieldPath) ||
        (fieldPath !== "" && !fieldPath.startsWith("/"))))
  )
    return null;
  return { store, username, uris, fieldPath };
}

/** Resolve only one named input containing the audited login_lookup locator. */
export function normalizeLoginLookupLocatorInputBinding(
  binding: unknown,
  inputs: unknown,
): NormalizedLoginLookupLocator | null {
  const inputName = namedLocatorInputName(binding, "secret_locator_input");
  if (
    !inputName ||
    !record(inputs) ||
    Object.keys(inputs).length !== 1 ||
    !Object.hasOwn(inputs, inputName)
  )
    return null;
  return normalizeLoginLookupLocatorBinding({
    secret_locator: inputs[inputName],
  });
}

function namedLocatorInputName(binding: unknown, key: string): string | null {
  if (
    !record(binding) ||
    Object.keys(binding).length !== 1 ||
    !Object.hasOwn(binding, key)
  )
    return null;
  const value = binding[key];
  const inputName =
    typeof value === "string"
      ? value.trim()
      : record(value) &&
          Object.keys(value).length === 1 &&
          typeof value.name === "string"
        ? value.name.trim()
        : "";
  return inputName &&
    inputName.length <= 128 &&
    !/[\u0000-\u001f\u007f]/.test(inputName) &&
    !hasUnsafeConnectReferenceCharacter(inputName)
    ? inputName
    : null;
}

export type NormalizedEnvVarLocator = { name: string };

/** Parse the audited `env_var` locator: only its opaque variable name survives. */
export function normalizeEnvVarLocatorBinding(
  binding: unknown,
): NormalizedEnvVarLocator | null {
  if (
    !record(binding) ||
    Object.keys(binding).length !== 1 ||
    !record(binding.secret_locator)
  )
    return null;
  const locator = binding.secret_locator;
  if (
    Object.keys(locator).some((key) => !["kind", "name"].includes(key)) ||
    locator.kind !== "env_var"
  )
    return null;
  const name = locator.name;
  if (typeof name !== "string" || name.trim() !== name) return null;
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)) return null;
  return { name };
}

/** Resolve only a single named input containing an `env_var` locator. */
export function normalizeEnvVarLocatorInputBinding(
  binding: unknown,
  inputs: unknown,
): NormalizedEnvVarLocator | null {
  const inputName = namedLocatorInputName(binding, "secret_locator_input");
  if (
    !inputName ||
    !record(inputs) ||
    Object.keys(inputs).length !== 1 ||
    !Object.hasOwn(inputs, inputName)
  )
    return null;
  return normalizeEnvVarLocatorBinding({ secret_locator: inputs[inputName] });
}
