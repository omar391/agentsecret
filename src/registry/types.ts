export type AccountStatus = "provisioning" | "active" | "suspended" | "deleted";

export interface CustomerAccount {
  id: string;
  status: AccountStatus;
  name: string;
  email: string | null;
  avatarUrl: string;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface CustomerIdentity {
  id: string;
  accountId: string;
  provider: string;
  providerSubject: string;
  email: string | null;
  emailVerified: boolean;
  profile: Record<string, unknown>;
  status: "active" | "pending";
  createdAt: number;
  updatedAt: number;
}

export interface AccountTombstone {
  accountId: string;
  reason: string;
  deletedAt: number;
}

export interface IdentityTombstone {
  provider: string;
  providerSubject: string;
  accountId: string;
  deletedAt: number;
}

export interface IdentityInput {
  provider: string;
  providerSubject: string;
  email?: string | null;
  emailVerified?: boolean;
  profile?: Record<string, unknown>;
}

export interface ProfileInput {
  name?: string;
  email?: string | null;
  avatarUrl?: string;
}

export interface AccountAuthorityState {
  status: AccountStatus;
  tombstoned: boolean;
  activatedAt: number | null;
  epoch: number;
  /** Whether a deletion retry window is currently open (the credential hash stays internal). */
  hasDeletionCapability?: boolean;
  deletionDeadline?: { exp: number } | null;
}
