import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { withProviderCredentialLock } from "./store";

export type CompanionProviderMode =
  | "bitwarden-secrets-manager"
  | "bitwarden-password-manager"
  | "onepassword-connect"
  | "onepassword-service-account"
  | "lastpass";

export interface ProviderCredentialBinding {
  server: string;
  tenant: string;
  connectionId: string;
  /** Owner-config revision; edits receive a separate local credential binding. */
  connectionRevision: number;
  providerMode: CompanionProviderMode;
}

interface StoredCredential {
  schema: "agentsecret/provider-credential/v2";
  binding: ProviderCredentialBinding;
  credential: string;
}

export interface CredentialBackend {
  read(key: string): string | undefined;
  write(key: string, value: string): void;
  delete(key: string): void;
}

function canonicalBinding(binding: ProviderCredentialBinding): string {
  if (
    !binding ||
    !/^[A-Za-z0-9_-]{1,80}$/.test(binding.tenant) ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(binding.connectionId) ||
    !Number.isSafeInteger(binding.connectionRevision) ||
    binding.connectionRevision < 1 ||
    ![
      "bitwarden-secrets-manager",
      "bitwarden-password-manager",
      "onepassword-connect",
      "onepassword-service-account",
      "lastpass",
    ].includes(binding.providerMode)
  )
    throw new Error("provider_credential_binding_invalid");

  let url: URL;
  try {
    url = new URL(binding.server);
  } catch {
    throw new Error("provider_credential_binding_invalid");
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.origin !== binding.server.replace(/\/$/, "")
  )
    throw new Error("provider_credential_binding_invalid");

  return JSON.stringify({
    server: url.origin,
    tenant: binding.tenant,
    connectionId: binding.connectionId,
    connectionRevision: binding.connectionRevision,
    providerMode: binding.providerMode,
  });
}

function keyForBinding(canonical: string): string {
  return createHash("sha256").update(canonical).digest("base64url");
}

/**
 * Keep provider credentials in a local OS credential store, partitioned by
 * server, customer account, connection ID and provider mode. A lookup for a
 * different provider or tenant cannot fall through to another binding.
 */
export class AccountBoundProviderCredentials {
  constructor(private readonly backend: CredentialBackend) {}

  async put(
    binding: ProviderCredentialBinding,
    credential: string,
  ): Promise<void> {
    const canonical = canonicalBinding(binding);
    if (
      typeof credential !== "string" ||
      credential.length < 1 ||
      credential.length > 8192 ||
      /[\u0000-\u001f\u007f]/.test(credential)
    )
      throw new Error("provider_credential_invalid");
    const stored: StoredCredential = {
      schema: "agentsecret/provider-credential/v2",
      binding: JSON.parse(canonical) as ProviderCredentialBinding,
      credential,
    };
    const key = keyForBinding(canonical);
    await withProviderCredentialLock(() => {
      const previous = this.backend.read(key);
      if (previous !== undefined) this.getUnlocked(canonical, key);
      try {
        this.backend.write(key, JSON.stringify(stored));
        if (this.getUnlocked(canonical, key) !== credential)
          throw new Error("provider_credential_store_verification_failed");
      } catch {
        try {
          if (previous === undefined) this.backend.delete(key);
          else this.backend.write(key, previous);
        } catch {
          throw new Error("provider_credential_store_recovery_failed");
        }
        throw new Error("provider_credential_store_write_failed");
      }
    });
  }

  async get(binding: ProviderCredentialBinding): Promise<string | undefined> {
    const canonical = canonicalBinding(binding);
    const key = keyForBinding(canonical);
    return withProviderCredentialLock(() => this.getUnlocked(canonical, key));
  }

  private getUnlocked(canonical: string, key: string): string | undefined {
    const value = this.backend.read(key);
    if (value === undefined) return undefined;
    let stored: StoredCredential;
    try {
      stored = JSON.parse(value) as StoredCredential;
    } catch {
      throw new Error("provider_credential_store_corrupt");
    }
    if (
      !stored ||
      stored.schema !== "agentsecret/provider-credential/v2" ||
      canonicalBinding(stored.binding) !== canonical ||
      typeof stored.credential !== "string" ||
      !stored.credential
    )
      throw new Error("provider_credential_binding_mismatch");
    return stored.credential;
  }

  async delete(binding: ProviderCredentialBinding): Promise<void> {
    const key = keyForBinding(canonicalBinding(binding));
    await withProviderCredentialLock(() => this.backend.delete(key));
  }
}

/** macOS first-release backend: provider values never fall back to local files. */
export function macOsKeychainProviderCredentials(): AccountBoundProviderCredentials {
  if (process.platform !== "darwin")
    throw new Error("provider_credential_store_unsupported");
  const service = "AgentSecret-provider-v2";
  const backend: CredentialBackend = {
    read(key) {
      try {
        const encoded = execFileSync(
          "/usr/bin/security",
          ["find-generic-password", "-a", key, "-s", service, "-w"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        ).trim();
        return Buffer.from(encoded, "base64url").toString("utf8");
      } catch (error) {
        if (
          error &&
          typeof error === "object" &&
          "status" in error &&
          error.status === 44
        )
          return undefined;
        throw new Error("provider_credential_store_unavailable");
      }
    },
    write(key, value) {
      const encoded = Buffer.from(value).toString("base64url");
      try {
        execFileSync("/usr/bin/security", ["-i"], {
          input: `add-generic-password -U -a "${key}" -s "${service}" -w "${encoded}"\n`,
          stdio: ["pipe", "ignore", "pipe"],
        });
      } catch {
        throw new Error("provider_credential_store_unavailable");
      }
    },
    delete(key) {
      try {
        execFileSync(
          "/usr/bin/security",
          ["delete-generic-password", "-a", key, "-s", service],
          { stdio: "ignore" },
        );
      } catch (error) {
        if (
          error &&
          typeof error === "object" &&
          "status" in error &&
          error.status === 44
        )
          return;
        throw new Error("provider_credential_store_unavailable");
      }
    },
  };
  return new AccountBoundProviderCredentials(backend);
}
