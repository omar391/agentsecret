import type { RegistryDatabase } from "./registry/database";

/**
 * Platform-neutral environment bindings.
 *
 * Every member the product path reads is declared here explicitly; the index signature
 * admits deployment-specific extras (for example the Cloudflare assets binding, which only
 * the Worker entry consumes through its own adapter). The interface deliberately does not
 * extend the generated Cloudflare binding surface, so the public Node/SQLite snapshot
 * compiles without the private Worker type declarations.
 */
export interface Env {
  /** D1 is retained for local development; production adapts Turso to this SQL surface. */
  DB?: RegistryDatabase;
  /** Explicit storage selection prevents production from falling back to a D1 binding. */
  REGISTRY_BACKEND?: "d1" | "turso";
  TURSO_DATABASE_URL?: string;
  TURSO_AUTH_TOKEN?: string;
  MCP_AUTH_TOKEN?: string;
  VAULT_KEYS?: string;
  VAULT_ACTIVE_KEY?: string;
  OAUTH_CLIENTS?: string;
  WORKLOAD_TRUST?: string;
  PUBLIC_ORIGIN?: string;
  MONTHLY_ALLOWANCE?: string;
  TENANTS?: string;
  /**
   * Customer social sign-in provider applications. Registered outside this deployment, so they are
   * configuration: a provider whose id/secret pair is absent or blank fails closed with
   * `501 feature_not_configured`. Provider endpoints are fixed in `src/auth/providers.ts` and are
   * not configurable, so no environment value can redirect an identity proof to another server.
   */
  GITHUB_OAUTH_CLIENT_ID?: string;
  GITHUB_OAUTH_CLIENT_SECRET?: string;
  GOOGLE_OIDC_CLIENT_ID?: string;
  GOOGLE_OIDC_CLIENT_SECRET?: string;
  /**
   * The account-authority namespace. Cloudflare binds the SECURITY Durable
   * Object namespace; a Node host supplies the same narrow dispatcher shape
   * from its in-process authority, so only this one member of the generated
   * binding surface is overridden for platform-neutral use.
   */
  SECURITY?: {
    getByName(tenant: string): {
      dispatch(command: unknown): Promise<unknown>;
    };
  };
  [key: string]: unknown;
}
/**
 * The only execution-context capability the product path uses. Each platform supplies its
 * own implementation: Cloudflare hands the Worker its ExecutionContext, a Node host hands a
 * fire-and-forget wrapper. No other member of that context is ever read by product code.
 */
export interface BackgroundContext {
  waitUntil(promise: Promise<unknown>): void;
}

export interface ConnectLoginFindSelector {
  kind: "login_lookup";
  /** Owner-pinned title avoids a vault-wide search. */
  title: string;
  /** Exact owner-approved login identity, checked inside the provider boundary. */
  username: string;
  uris: string[];
  /** Exact Connect field ID already pinned by secretId. */
  fieldId: string;
  /** Optional legacy locator path, matched exactly and never interpreted as a field ID. */
  fieldPath?: string;
}
export type SecretFindSelector =
  { kind?: never; title: string; fieldId?: string } | ConnectLoginFindSelector;
export interface SecretPolicy {
  alias: string;
  description: string;
  allowedDomains: string[];
  allowedMethods: string[];
  pathPatterns?: string[];
  injectionType:
    "bearer" | "header" | "basic" | "query_param" | "body_placeholder";
  headerName?: string;
  username?: string;
  queryParamName?: string;
  secretId?: string;
  /** Internal account-owned vault connection. Omitted only for legacy default-vault policies. */
  connectionId?: string;
  connectionRevision?: number;
  /** Optional owner-approved exact Connect locator for safe agent/CLI find. */
  findSelector?: SecretFindSelector;
  /** Explicit owner grant for CLI/MCP vault writes; omitted means read-only. */
  secretWrite?: { create?: boolean; update?: boolean; delete?: boolean };
  cliConfig?: { envVarName?: string };
}
export interface Session {
  tenant: string;
  purpose: "control" | "agent";
  audience: string;
  scopes: string[];
  aliases?: string[];
  /** Canonical policies consented for this agent grant; a policy edit requires fresh consent. */
  policyBindings?: Record<string, string>;
  /** Stable trusted workload identity used to recover write receipts across DPoP key rotation. */
  agentId?: string;
  jkt?: string;
  exp: number;
  epoch: number;
  parent?: string;
  /** A control credential superseded by rotation; retained for grant and agent bindings. */
  superseded?: boolean;
  /**
   * When this customer session was first issued, and when its credential was last rotated.
   * Both are absolute epoch seconds and are set by the session issuer, never by a client. The
   * absolute lifetime is `exp` and rotation does not move it: `createdAt` is what makes "is a
   * rotation due" answerable without extending anything.
   */
  createdAt?: number;
  refreshedAt?: number;
}
export interface Principal extends Session {
  hash: string;
  bootstrap?: boolean;
}
export type { Proof } from "../protocol/proof-types";
export interface Grant {
  kind: "code" | "device";
  status: "pending" | "approved";
  audience: string;
  exp: number;
  sessionExp?: number;
  clientId: string;
  redirectUri?: string;
  challenge?: string;
  jkt?: string;
  userCode?: string;
  parent?: string;
  epoch: number;
  scopes: string[];
  /** Device requested scopes are bounded by owner-reviewed alias policy. */
  requestedScopes?: string[];
  aliases?: string[];
  /** Captured atomically when the human approves the grant. */
  policyBindings?: Record<string, string>;
  lastPoll?: number;
}
export interface ProxyRequestParams {
  secret_alias: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: unknown;
  response_mode?: "git";
}
export interface JSONRPCRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, any>;
}
export interface JSONRPCResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}
export interface BitwardenVaultConfig {
  type: "bitwarden";
  accessToken: string;
  apiUrl?: string;
  identityUrl?: string;
}

export interface OnePasswordConnectVaultConfig {
  type: "onepassword-connect";
  accessToken: string;
  apiUrl: string;
  vaultId: string;
}

/** Metadata only. Its service-account token stays in the local companion's OS store. */
export interface OnePasswordServiceAccountVaultConfig {
  type: "onepassword-service-account";
  vaultId: string;
}

/** Local Bitwarden Password Manager profile; decrypted data and credentials stay on device. */
export interface BitwardenPasswordManagerVaultConfig {
  type: "bitwarden-password-manager";
  profileId: string;
}

/** Local LastPass profile; decrypted data and credentials stay on device. */
export interface LastPassVaultConfig {
  type: "lastpass";
  profileId: string;
}

export type VaultConfig =
  | BitwardenVaultConfig
  | OnePasswordConnectVaultConfig
  | OnePasswordServiceAccountVaultConfig
  | BitwardenPasswordManagerVaultConfig
  | LastPassVaultConfig;

export interface VaultConnection {
  id: string;
  alias: string;
  provider: VaultConfig["type"];
  revision: number;
  createdAt: number;
  updatedAt: number;
}
