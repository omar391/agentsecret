export type ViewMode = "landing" | "dashboard";

export type DashboardTab =
  | "overview"
  | "vaults"
  | "secrets"
  | "policies"
  | "simulator"
  | "oauth"
  | "audit"
  | "integrations";

export const DASHBOARD_TABS: DashboardTab[] = [
  "overview",
  "vaults",
  "secrets",
  "policies",
  "simulator",
  "oauth",
  "audit",
  "integrations",
];

export interface UserSession {
  id: string;
  name: string;
  email: string;
  avatarUrl: string;
  provider: "github" | "google" | "customer";
  apiKey?: string;
  onboarding?: { complete: boolean; displayName: string | null };
  plan: "free" | "pro" | "enterprise" | "self-hosted";
  quotaUsed: number;
  quotaLimit: number;
}

export interface VaultConnection {
  id: string;
  alias: string;
  provider: string;
  revision: number;
  capabilities?: {
    read: boolean;
    create: boolean;
    update: boolean;
    conditionalUpdate: boolean;
    verifyAfterWrite: boolean;
    delete: boolean;
  };
}

export type ProviderMode =
  | "bitwarden-secrets-manager"
  | "bitwarden-password-manager"
  | "onepassword-connect"
  | "onepassword-service-account"
  | "lastpass";

export type ReleaseProviderMode =
  | "bitwarden-secrets-manager"
  | "bitwarden-password-manager"
  | "onepassword-service-account"
  | "lastpass";

export type PrivateInputRequest = {
  requestId: string;
  alias: string;
  intent: "create" | "update" | "ensure" | "delete";
  target: string;
  connectionId: string;
  expiresAt: number;
  status: "pending" | "fulfilling" | "unknown" | "saved";
};

export interface ProviderCapability {
  status: "implemented" | "requires-companion" | "unsupported";
  read: boolean;
  create: boolean;
  update: boolean;
  conditionalUpdate: boolean;
  verifyAfterWrite: boolean;
  delete: boolean;
  reason: string;
}

export const PROVIDER_MODE_LABELS: Record<ReleaseProviderMode, string> = {
  "bitwarden-secrets-manager": "Bitwarden Secrets Manager",
  "bitwarden-password-manager": "Bitwarden Password Manager",
  "onepassword-service-account": "1Password service account",
  lastpass: "LastPass",
};
