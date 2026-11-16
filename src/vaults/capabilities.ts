export type ProviderMode =
  | "bitwarden-secrets-manager"
  | "bitwarden-password-manager"
  | "onepassword-connect"
  | "onepassword-service-account"
  | "lastpass";

/** Modes promised by the first four-mode release. */
export const RELEASE_PROVIDER_MODES = [
  "bitwarden-secrets-manager",
  "bitwarden-password-manager",
  "onepassword-service-account",
  "lastpass",
] as const satisfies readonly ProviderMode[];

export type ReleaseProviderMode = (typeof RELEASE_PROVIDER_MODES)[number];

export interface ProviderCapabilities {
  status: "implemented" | "requires-companion" | "unsupported";
  read: boolean;
  create: boolean;
  update: boolean;
  conditionalUpdate: boolean;
  verifyAfterWrite: boolean;
  delete: boolean;
  /** Static explanation suitable for customer and agent capability discovery. */
  reason: string;
}

/** Low-level adapter primitives; public connection capabilities are tracked separately below. */
export const connectCapabilities = Object.freeze({
  read: true,
  create: true,
  update: true,
  replace: true,
  delete: true,
  conditionalUpdate: false,
  readAfterWriteVerification: true,
});

const CAPABILITIES: Record<ProviderMode, ProviderCapabilities> = {
  "bitwarden-secrets-manager": {
    status: "implemented",
    read: true,
    create: false,
    update: false,
    conditionalUpdate: false,
    verifyAfterWrite: false,
    delete: false,
    reason: "The current adapter implements authenticated read only.",
  },
  "bitwarden-password-manager": {
    status: "requires-companion",
    read: true,
    create: false,
    update: false,
    conditionalUpdate: false,
    verifyAfterWrite: false,
    delete: false,
    reason:
      "An owner-bound Fastflow local companion reads exact Bitwarden item fields after cloud authorization. Decrypted item JSON and values stay in process. Protected create/update/ensure are implemented for qualified companions but remain disabled until live acceptance; delete and conditional updates are unsupported, and the cloud has no BWP adapter.",
  },
  "onepassword-connect": {
    status: "implemented",
    read: connectCapabilities.read,
    create: connectCapabilities.create,
    update: connectCapabilities.update,
    conditionalUpdate: false,
    verifyAfterWrite: connectCapabilities.readAfterWriteVerification,
    delete: true,
    reason:
      "Owner control supports customer read/create/update/delete and agent create/update/delete when the agent has secrets:write plus a matching per-alias owner grant; writes use post-write verification. Conditional updates are not supported.",
  },
  "onepassword-service-account": {
    status: "requires-companion",
    read: true,
    create: false,
    update: false,
    conditionalUpdate: false,
    verifyAfterWrite: false,
    delete: false,
    reason:
      "A locally configured, account-bound companion verifies its pinned vault and implements exact-field create, update, ensure, and custom-field delete with read-back verification after executor-bound cloud authorization. Values stay in the local process. Public write flags remain disabled until isolated live acceptance; built-in fields cannot be deleted. This is not a Connect token.",
  },
  lastpass: {
    status: "requires-companion",
    read: true,
    create: false,
    update: false,
    conditionalUpdate: false,
    verifyAfterWrite: false,
    delete: false,
    reason:
      "A dedicated account-bound local companion reads exact LastPass CLI item fields after cloud authorization and keeps the full item JSON in process memory. Noninteractive stdin create/update/ensure are implemented for qualified companions but remain disabled until live acceptance; delete, attachments, and unsupported fields are disabled.",
  },
};

export function providerCapabilities(mode: ProviderMode): ProviderCapabilities {
  return { ...CAPABILITIES[mode] };
}

export function listProviderCapabilities(): Record<
  ReleaseProviderMode,
  ProviderCapabilities
> {
  return Object.fromEntries(
    RELEASE_PROVIDER_MODES.map((mode) => [mode, { ...CAPABILITIES[mode] }]),
  ) as Record<ReleaseProviderMode, ProviderCapabilities>;
}
