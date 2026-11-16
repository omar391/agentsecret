import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  Key,
  Database,
  Globe,
  CheckCircle,
  Copy,
  Zap,
  Play,
  List,
  Code2,
  Layers,
  LogOut,
  ArrowRight,
  ChevronRight,
} from "lucide-react";

type ViewMode = "landing" | "dashboard";
type DashboardTab =
  | "overview"
  | "vaults"
  | "secrets"
  | "policies"
  | "simulator"
  | "oauth"
  | "audit"
  | "integrations";
const DASHBOARD_TABS: DashboardTab[] = [
  "overview",
  "vaults",
  "secrets",
  "policies",
  "simulator",
  "oauth",
  "audit",
  "integrations",
];

interface UserSession {
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
interface VaultConnection {
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
type ProviderMode =
  | "bitwarden-secrets-manager"
  | "bitwarden-password-manager"
  | "onepassword-connect"
  | "onepassword-service-account"
  | "lastpass";
type ReleaseProviderMode =
  | "bitwarden-secrets-manager"
  | "bitwarden-password-manager"
  | "onepassword-service-account"
  | "lastpass";
type PrivateInputRequest = {
  requestId: string;
  alias: string;
  intent: "create" | "update" | "ensure" | "delete";
  target: string;
  connectionId: string;
  expiresAt: number;
  status: "pending" | "fulfilling" | "unknown" | "saved";
};
interface ProviderCapability {
  status: "implemented" | "requires-companion" | "unsupported";
  read: boolean;
  create: boolean;
  update: boolean;
  conditionalUpdate: boolean;
  verifyAfterWrite: boolean;
  delete: boolean;
  reason: string;
}
const PROVIDER_MODE_LABELS: Record<ReleaseProviderMode, string> = {
  "bitwarden-secrets-manager": "Bitwarden Secrets Manager",
  "bitwarden-password-manager": "Bitwarden Password Manager",
  "onepassword-service-account": "1Password service account",
  lastpass: "LastPass",
};

export default function App() {
  const [view, setView] = useState<ViewMode>("landing");
  const [activeTab, setActiveTab] = useState<DashboardTab>("overview");
  const [user, setUser] = useState<UserSession | null>(null);
  const [, setIsLoadingUser] = useState(true);
  const [showAuthModal, setShowAuthModal] = useState(false);
  // Onboarding is the customer's own display name; it never asks for an email confirmation.
  const [onboardingName, setOnboardingName] = useState("");
  const [onboardingStatus, setOnboardingStatus] = useState<
    "idle" | "saving" | "saved" | "error"
  >("idle");
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);

  // Vault configuration state
  const [vaultProvider, setVaultProvider] = useState<
    | "bitwarden_secrets"
    | "bitwarden_password"
    | "onepassword"
    | "onepassword_service_account"
    | "lastpass"
  >("bitwarden_secrets");

  // Bitwarden Secrets Manager (BWS)
  const [bwsToken, setBwsToken] = useState("");

  const [companionProfileId, setCompanionProfileId] = useState("");
  const [serviceAccountVaultId, setServiceAccountVaultId] = useState("");
  const [opToken, setOpToken] = useState("");
  const [connectUrl, setConnectUrl] = useState("");
  const [connectVault, setConnectVault] = useState("");

  const [vaultSaveStatus, setVaultSaveStatus] = useState<string | null>(null);
  const [vaultConnections, setVaultConnections] = useState<VaultConnection[]>(
    [],
  );
  const [providerModes, setProviderModes] = useState<
    Partial<Record<ProviderMode, ProviderCapability>>
  >({});
  const [connectionAlias, setConnectionAlias] = useState("");
  const [replaceConnectionId, setReplaceConnectionId] = useState("");
  const [selectedConnectionId, setSelectedConnectionId] = useState("");
  const [saveConnectionId, setSaveConnectionId] = useState("");
  const [saveMode, setSaveMode] = useState<"create" | "update" | "delete">(
    "create",
  );
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  const [saveTitle, setSaveTitle] = useState("");
  const [saveReference, setSaveReference] = useState("");
  const [saveValue, setSaveValue] = useState("");
  const [saveOperationId, setSaveOperationId] = useState("");
  const [saveStatus, setSaveStatus] = useState<
    "idle" | "saving" | "saved" | "error" | "unknown"
  >("idle");
  const [compareStatus, setCompareStatus] = useState<
    "idle" | "checking" | "match" | "different" | "error"
  >("idle");
  const [ensureStatus, setEnsureStatus] = useState<
    "idle" | "checking" | "unchanged" | "updated" | "error" | "unknown"
  >("idle");
  const [savedReference, setSavedReference] = useState("");
  const saveInFlight = useRef(false);
  const compareRequestVersion = useRef(0);
  const [privateInputRequests, setPrivateInputRequests] = useState<
    PrivateInputRequest[]
  >([]);
  const [privateInputNextCursor, setPrivateInputNextCursor] = useState<
    string | null
  >(null);
  const [privateInputLoadingMore, setPrivateInputLoadingMore] = useState(false);
  const privateInputPaginationStarted = useRef(false);
  const [privateInputDrafts, setPrivateInputDrafts] = useState<
    Record<string, string>
  >({});
  const [privateInputSubmitting, setPrivateInputSubmitting] = useState<
    string | null
  >(null);
  const [privateInputFeedback, setPrivateInputFeedback] = useState<
    Record<string, string>
  >({});
  const [findConnectionId, setFindConnectionId] = useState("");
  const [findReference, setFindReference] = useState("");
  const [findStatus, setFindStatus] = useState<
    "idle" | "searching" | "found" | "error"
  >("idle");
  const [findResult, setFindResult] = useState<{
    provider: string;
    reference: string;
  } | null>(null);
  const findRequestVersion = useRef(0);

  useEffect(() => {
    findRequestVersion.current++;
    setFindStatus("idle");
    setFindResult(null);
  }, [user?.id]);

  useEffect(() => {
    if (!user || view !== "dashboard" || activeTab !== "secrets") {
      setPrivateInputRequests([]);
      setPrivateInputNextCursor(null);
      privateInputPaginationStarted.current = false;
      return;
    }
    let stopped = false;
    const controller = new AbortController();
    const refresh = async () => {
      try {
        const response = await fetch("/api/user/secrets/private-inputs", {
          signal: controller.signal,
        });
        const data = await response.json().catch(() => null);
        if (!stopped && response.ok && Array.isArray(data?.requests)) {
          setPrivateInputRequests((current) => {
            const freshIds = new Set(
              data.requests.map(
                (request: PrivateInputRequest) => request.requestId,
              ),
            );
            const stillUnexpired = current.filter(
              (request) =>
                !freshIds.has(request.requestId) &&
                (request.status !== "pending" ||
                  request.expiresAt * 1000 > Date.now()),
            );
            return [...data.requests, ...stillUnexpired];
          });
          if (!privateInputPaginationStarted.current)
            setPrivateInputNextCursor(
              typeof data.nextCursor === "string" ? data.nextCursor : null,
            );
        }
      } catch {
        // The save panel remains usable if pending owner requests cannot refresh.
      }
    };
    void refresh();
    const timer = setInterval(() => void refresh(), 10000);
    return () => {
      stopped = true;
      controller.abort();
      clearInterval(timer);
    };
  }, [activeTab, user?.id, view]);

  const handleLoadMorePrivateInputs = async () => {
    const cursor = privateInputNextCursor;
    if (!cursor || privateInputLoadingMore) return;
    setPrivateInputLoadingMore(true);
    try {
      const response = await fetch(
        `/api/user/secrets/private-inputs?cursor=${encodeURIComponent(cursor)}`,
      );
      const data = await response.json().catch(() => null);
      if (response.ok && Array.isArray(data?.requests)) {
        privateInputPaginationStarted.current = true;
        setPrivateInputRequests((current) => {
          const known = new Set(current.map((request) => request.requestId));
          return [
            ...current,
            ...data.requests.filter(
              (request: PrivateInputRequest) => !known.has(request.requestId),
            ),
          ];
        });
        setPrivateInputNextCursor(
          typeof data.nextCursor === "string" ? data.nextCursor : null,
        );
      }
    } catch {
      // Keep the current page available when loading older requests fails.
    } finally {
      setPrivateInputLoadingMore(false);
    }
  };

  const clearVaultCredentialDraft = () => {
    setBwsToken("");
    setCompanionProfileId("");
    setServiceAccountVaultId("");
    setOpToken("");
    setConnectUrl("");
    setConnectVault("");
    setConnectionAlias("");
    setReplaceConnectionId("");
    setVaultProvider("bitwarden_secrets");
  };

  // Policies state
  const [newAlias, setNewAlias] = useState("");
  const [newDomains, setNewDomains] = useState("api.github.com");
  const [newMethods, setNewMethods] = useState("GET, POST");
  const [newInjectionType, setNewInjectionType] = useState<
    "bearer" | "body_placeholder"
  >("bearer");
  const [newDesc, setNewDesc] = useState("");
  const [newSecretId, setNewSecretId] = useState("");
  const [newFindLoginEnabled, setNewFindLoginEnabled] = useState(false);
  const [newFindLoginTitle, setNewFindLoginTitle] = useState("");
  const [newFindLoginUsername, setNewFindLoginUsername] = useState("");
  const [newFindLoginUris, setNewFindLoginUris] = useState("");
  const [newFindLoginFieldPath, setNewFindLoginFieldPath] = useState("");
  const [newSecretWriteCreate, setNewSecretWriteCreate] = useState(false);
  const [newSecretWriteUpdate, setNewSecretWriteUpdate] = useState(false);
  const [newSecretWriteDelete, setNewSecretWriteDelete] = useState(false);
  const [editingLoginAlias, setEditingLoginAlias] = useState<string | null>(
    null,
  );
  const [editLoginEnabled, setEditLoginEnabled] = useState(false);
  const [editLoginTitle, setEditLoginTitle] = useState("");
  const [editLoginUsername, setEditLoginUsername] = useState("");
  const [editLoginUris, setEditLoginUris] = useState("");
  const [editLoginFieldPath, setEditLoginFieldPath] = useState("");
  const [policies, setPolicies] = useState<
    Array<{
      alias: string;
      domains: string;
      methods: string;
      injectionType: string;
      desc: string;
      connectionId?: string;
      secretId?: string;
      connectionRevision?: number;
      findSelector?: {
        kind?: string;
        title: string;
        username?: string;
        uris?: string[];
        fieldId?: string;
        fieldPath?: string;
      };
    }>
  >([]);

  const [executorApproval, setExecutorApproval] = useState("");
  const [executorFeedback, setExecutorFeedback] = useState<string | null>(null);
  const [browserExecutors, setBrowserExecutors] = useState<
    Array<{
      executorId: string;
      thumbprint: string;
      createdAt: number;
      enrolledAt: number;
    }>
  >([]);
  const [browserGrants, setBrowserGrants] = useState<
    Array<{
      grantId: string;
      executorId: string;
      alias: string;
      origin: string;
      kinds: string[];
      fieldSelector: string;
      expiresAt: number;
      redeemedAt: number | null;
      revokedAt: number | null;
    }>
  >([]);
  const [grantExecutorId, setGrantExecutorId] = useState("");
  const [grantAlias, setGrantAlias] = useState("");
  const [grantOrigin, setGrantOrigin] = useState("https://");
  const [grantActions, setGrantActions] = useState("fill,totp");
  const [grantSelector, setGrantSelector] = useState("#password");
  const [grantFeedback, setGrantFeedback] = useState<string | null>(null);

  const refreshExecutorState = async () => {
    const [identityResponse, grantResponse] = await Promise.all([
      fetch("/api/executor/identities"),
      fetch("/api/executor/grants"),
    ]);
    const identityData = await identityResponse.json().catch(() => null);
    const grantData = await grantResponse.json().catch(() => null);
    if (identityResponse.ok && Array.isArray(identityData?.executors))
      setBrowserExecutors(identityData.executors);
    if (grantResponse.ok && Array.isArray(grantData?.grants))
      setBrowserGrants(grantData.grants);
  };

  useEffect(() => {
    if (!user || view !== "dashboard" || activeTab !== "policies") return;
    const controller = new AbortController();
    const load = async () => {
      try {
        const [identityResponse, grantResponse] = await Promise.all([
          fetch("/api/executor/identities", { signal: controller.signal }),
          fetch("/api/executor/grants", { signal: controller.signal }),
        ]);
        const identityData = await identityResponse.json().catch(() => null);
        const grantData = await grantResponse.json().catch(() => null);
        if (identityResponse.ok && Array.isArray(identityData?.executors))
          setBrowserExecutors(identityData.executors);
        if (grantResponse.ok && Array.isArray(grantData?.grants))
          setBrowserGrants(grantData.grants);
      } catch {
        // The executor panel stays usable and reports action failures locally.
      }
    };
    void load();
    return () => controller.abort();
  }, [activeTab, user, view]);

  // Egress Simulator
  const [simAlias, setSimAlias] = useState("");
  const [simUrl, setSimUrl] = useState("https://api.github.com/zen");
  const [simMethod, setSimMethod] = useState("GET");
  const [simLoading, setSimLoading] = useState(false);
  const [simResult, setSimResult] = useState<{
    status?: number;
    error?: string;
    data?: unknown;
    redactionsCount?: number;
  } | null>(null);

  const [dashboardNotice, setDashboardNotice] = useState<string | null>(null);
  const [auditLogs, setAuditLogs] = useState<
    Array<{
      at: string;
      alias: string;
      host: string;
      method: string;
      status: number;
    }>
  >([]);

  // Integration Snippet Tab

  // FAQ accordion state
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  useEffect(() => {
    // Check URL parameters for view.
    const params = new URLSearchParams(window.location.search);
    if (
      params.get("view") === "dashboard" ||
      params.get("auth") === "success"
    ) {
      setView("dashboard");
    }
    const requestedTab = params.get("tab");
    setActiveTab(
      DASHBOARD_TABS.includes(requestedTab as DashboardTab)
        ? (requestedTab as DashboardTab)
        : "overview",
    );
    checkAuthSession();
  }, []);

  const checkAuthSession = async () => {
    setIsLoadingUser(true);
    try {
      const res = await fetch("/api/auth/me");
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated && data.user) {
          setUser(data.user);
          setIsLoadingUser(false);
          return;
        }
      }
    } catch {
      // Fallback
    }

    setUser(null);
    setIsLoadingUser(false);
  };

  // The only sign-in path a customer has: the provider's own authorization page. There is no
  // operator page, no shared credential and no local shortcut to a session.
  const startSocialLogin = (provider: "github" | "google") => {
    window.location.href = "/auth/" + provider;
  };
  const handleOnboarding = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = onboardingName.trim();
    if (!name) return;
    setOnboardingStatus("saving");
    try {
      const res = await fetch("/api/user/onboarding", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      if (!res.ok) throw new Error("Onboarding rejected");
      setOnboardingStatus("saved");
      await checkAuthSession();
    } catch {
      setOnboardingStatus("error");
    }
  };
  const refreshPolicies = async (signal?: AbortSignal) => {
    const res = await fetch("/api/user/policies", { signal });
    if (!res.ok) throw new Error("Unable to load policies");
    const data = await res.json();
    if (signal?.aborted) return;
    setPolicies(
      data.policies.map((p: any) => ({
        alias: p.alias,
        domains: p.allowedDomains.join(", "),
        methods: p.allowedMethods.join(", "),
        injectionType: p.injectionType,
        desc: p.description,
        connectionId: p.connectionId,
        secretId: p.secretId,
        connectionRevision: p.connectionRevision,
        findSelector: p.findSelector,
      })),
    );
  };
  const refreshVaultConnections = async (signal?: AbortSignal) => {
    const res = await fetch("/api/user/vault-connections", { signal });
    if (!res.ok) throw new Error("Unable to load vault connections");
    const data = await res.json();
    if (signal?.aborted) return;
    setVaultConnections(data.connections);
    setProviderModes(data.providerCapabilities || {});
    setSelectedConnectionId((current: string) =>
      data.connections.some(
        (connection: VaultConnection) => connection.id === current,
      )
        ? current
        : data.connections[0]?.id || "",
    );
  };
  useEffect(() => {
    if (!newFindLoginEnabled) return;
    const selectedConnection = vaultConnections.find(
      (connection) => connection.id === selectedConnectionId,
    );
    if (selectedConnection?.provider !== "onepassword-connect")
      setNewFindLoginEnabled(false);
  }, [newFindLoginEnabled, selectedConnectionId, vaultConnections]);
  useEffect(() => {
    const controller = new AbortController();
    clearVaultCredentialDraft();
    setPolicies([]);
    setVaultConnections([]);
    setProviderModes({});
    setSaveConnectionId("");
    setSaveTitle("");
    setSaveValue("");
    setSaveOperationId("");
    setSaveStatus("idle");
    setSavedReference("");
    saveInFlight.current = false;
    setFindConnectionId("");
    setFindReference("");
    setFindStatus("idle");
    setFindResult(null);
    setSimAlias("");
    setSimResult(null);
    if (user) {
      refreshPolicies(controller.signal).catch(() => {
        if (!controller.signal.aborted)
          setDashboardNotice("Policies could not be loaded.");
      });
      refreshVaultConnections(controller.signal).catch(() => {
        if (!controller.signal.aborted)
          setDashboardNotice("Vault connections could not be loaded.");
      });
    }
    return () => controller.abort();
  }, [user]);

  useEffect(() => {
    setSimAlias((selected) =>
      policies.some((p) => p.alias === selected)
        ? selected
        : policies[0]?.alias || "",
    );
  }, [policies]);

  useEffect(() => {
    if (user && activeTab === "audit")
      fetch("/api/user/audit")
        .then(async (res) => {
          if (!res.ok) throw new Error();
          const data = await res.json();
          setAuditLogs(data.logs);
        })
        .catch(() => setDashboardNotice("Audit records could not be loaded."));
  }, [user, activeTab]);
  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch {
      // ignore
    }
    setUser(null);
    clearVaultCredentialDraft();
    setView("landing");
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    if (id === "apiKey") {
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    } else {
      setCopiedSnippet(id);
      setTimeout(() => setCopiedSnippet(null), 2000);
    }
  };

  const handleSaveVault = async (e: React.FormEvent) => {
    e.preventDefault();
    setVaultSaveStatus("saving");
    try {
      const configPayload: any =
        vaultProvider === "bitwarden_secrets"
          ? { type: "bitwarden", accessToken: bwsToken }
          : vaultProvider === "bitwarden_password"
            ? {
                type: "bitwarden-password-manager",
                profileId: companionProfileId,
              }
            : vaultProvider === "onepassword_service_account"
              ? {
                  type: "onepassword-service-account",
                  vaultId: serviceAccountVaultId,
                }
              : vaultProvider === "lastpass"
                ? { type: "lastpass", profileId: companionProfileId }
                : vaultProvider === "onepassword" && replaceConnectionId
                  ? {
                      type: "onepassword-connect",
                      accessToken: opToken,
                      apiUrl: connectUrl,
                      vaultId: connectVault,
                    }
                  : null;
      if (!configPayload)
        throw new Error(
          "This provider is not supported in the strict broker profile.",
        );

      const res = await fetch("/api/user/vault-connections", {
        method: replaceConnectionId ? "PATCH" : "POST",
        headers: { "Content-Type": "application/json" },
        // No account identifier is sent: the server takes it from the session, so there is
        // nothing here a customer could point at somebody else's account.
        body: JSON.stringify({
          id: replaceConnectionId || undefined,
          alias: connectionAlias.trim(),
          config: configPayload,
        }),
      });

      if (res.ok) {
        setVaultSaveStatus("success");
        clearVaultCredentialDraft();
        await refreshVaultConnections();
      } else {
        setVaultSaveStatus("error");
      }
    } catch {
      setVaultSaveStatus("error");
    }
  };

  const handleSaveSecret = async (
    e: React.FormEvent,
  ): Promise<"saved" | "unknown" | "error"> => {
    e.preventDefault();
    if (
      saveInFlight.current ||
      compareStatus === "checking" ||
      ensureStatus === "checking"
    )
      return "error";
    const connection = vaultConnections.find(
      (item) => item.id === saveConnectionId,
    );
    const isUpdate = saveMode === "update";
    const isDelete = saveMode === "delete";
    if (
      !connection ||
      connection.provider !== "onepassword-connect" ||
      !(isDelete
        ? connection.capabilities?.delete
        : isUpdate
          ? connection.capabilities?.update
          : connection.capabilities?.create) ||
      (isUpdate || isDelete ? !saveReference.trim() : !saveTitle.trim()) ||
      (!isDelete && !saveValue) ||
      (isDelete && !deleteConfirmed)
    ) {
      setSaveStatus("error");
      return "error";
    }

    const retryingOperation = Boolean(saveOperationId);
    const operationId =
      saveOperationId || `save_${crypto.randomUUID().replace(/-/g, "")}`;
    setSaveOperationId(operationId);
    setSavedReference("");
    setSaveStatus("saving");
    saveInFlight.current = true;
    try {
      const res = await fetch(
        isDelete
          ? "/api/user/secrets/delete"
          : isUpdate
            ? "/api/user/secrets/update"
            : "/api/user/secrets/save",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            connectionId: connection.id,
            operationId,
            ...(isUpdate || isDelete
              ? { reference: saveReference.trim() }
              : { title: saveTitle.trim() }),
            ...(!isDelete ? { value: saveValue } : {}),
          }),
        },
      );
      const data = await res.json().catch(() => null);
      if (
        res.ok &&
        data?.status ===
          (isDelete ? "deleted" : isUpdate ? "updated" : "created") &&
        data?.verified === true &&
        typeof data?.reference === "string" &&
        data.reference.length > 0
      ) {
        setSavedReference(data.reference);
        setSaveTitle("");
        setSaveReference("");
        setSaveValue("");
        setSaveOperationId("");
        setDeleteConfirmed(false);
        setSaveStatus("saved");
        return "saved";
      } else if (
        retryingOperation ||
        res.ok ||
        res.status >= 500 ||
        data?.error === "save_outcome_unknown" ||
        data?.error === "save_in_progress"
      ) {
        // Keep the same operation ID and private input for an idempotent retry.
        setSaveStatus("unknown");
        return "unknown";
      } else {
        setSaveOperationId("");
        setSaveStatus("error");
        return "error";
      }
    } catch {
      // The request may have reached the provider. A retry must reuse this ID.
      setSaveStatus("unknown");
      return "unknown";
    } finally {
      saveInFlight.current = false;
    }
  };

  const handleCompareSecret = async () => {
    const connection = vaultConnections.find(
      (item) => item.id === saveConnectionId,
    );
    if (
      saveMode !== "update" ||
      !connection?.capabilities?.read ||
      !saveReference.trim() ||
      !saveValue
    ) {
      setCompareStatus("error");
      setSaveValue("");
      return;
    }
    const requestVersion = ++compareRequestVersion.current;
    setCompareStatus("checking");
    try {
      const response = await fetch("/api/user/secrets/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          connectionId: connection.id,
          reference: saveReference.trim(),
          value: saveValue,
        }),
      });
      const data = await response.json().catch(() => null);
      if (compareRequestVersion.current !== requestVersion) return;
      if (response.ok && typeof data?.matches === "boolean")
        setCompareStatus(data.matches ? "match" : "different");
      else setCompareStatus("error");
    } catch {
      if (compareRequestVersion.current === requestVersion)
        setCompareStatus("error");
    } finally {
      if (compareRequestVersion.current === requestVersion) setSaveValue("");
    }
  };

  const handleEnsureSecret = async () => {
    const connection = vaultConnections.find(
      (item) => item.id === saveConnectionId,
    );
    if (
      saveMode !== "update" ||
      connection?.provider !== "onepassword-connect" ||
      !connection.capabilities?.read ||
      !connection.capabilities?.update ||
      !saveReference.trim() ||
      !saveValue
    ) {
      setEnsureStatus("error");
      setSaveValue("");
      return;
    }
    if (saveInFlight.current || saveStatus === "unknown") {
      setEnsureStatus("error");
      return;
    }
    const retryingOperation = ensureStatus === "unknown" && !!saveOperationId;
    const operationId = retryingOperation
      ? saveOperationId
      : `ensure_${crypto.randomUUID().replace(/-/g, "")}`;
    setSaveOperationId(operationId);
    setSavedReference("");
    setEnsureStatus("checking");
    saveInFlight.current = true;
    try {
      const response = await fetch("/api/user/secrets/ensure", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          connectionId: connection.id,
          operationId,
          reference: saveReference.trim(),
          value: saveValue,
        }),
      });
      const data = await response.json().catch(() => null);
      if (
        response.ok &&
        ["unchanged", "updated"].includes(data?.status) &&
        data?.verified === true &&
        typeof data.reference === "string"
      ) {
        setEnsureStatus(data.status);
        setSavedReference(data.reference);
        setSaveOperationId("");
        setSaveValue("");
        return;
      }
      if (data?.error === "secret_ensure_read_failed") {
        setEnsureStatus("error");
        setSaveOperationId("");
        setSaveValue("");
      } else if (
        retryingOperation ||
        response.ok ||
        response.status >= 500 ||
        ["save_outcome_unknown", "save_in_progress"].includes(data?.error)
      ) {
        setEnsureStatus("unknown");
      } else {
        setEnsureStatus("error");
        setSaveOperationId("");
        setSaveValue("");
      }
    } catch {
      setEnsureStatus("unknown");
    } finally {
      saveInFlight.current = false;
    }
  };

  const handleFulfillPrivateInput = async (
    e: React.FormEvent,
    request: PrivateInputRequest,
  ) => {
    e.preventDefault();
    const value = privateInputDrafts[request.requestId] ?? "";
    if (!value || privateInputSubmitting) return;
    setPrivateInputSubmitting(request.requestId);
    setPrivateInputFeedback((current) => ({
      ...current,
      [request.requestId]: "Saving…",
    }));
    try {
      const response = await fetch("/api/user/secrets/private-inputs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requestId: request.requestId, value }),
      });
      const data = await response.json().catch(() => null);
      if (
        response.ok &&
        ["created", "updated", "unchanged"].includes(data?.status) &&
        data?.verified === true &&
        typeof data?.reference === "string"
      ) {
        setPrivateInputDrafts((current) => {
          const next = { ...current };
          delete next[request.requestId];
          return next;
        });
        setPrivateInputFeedback((current) => ({
          ...current,
          [request.requestId]:
            data.status === "unchanged"
              ? `Already matched; no write was made: ${data.reference}`
              : data.status === "updated"
                ? `Updated and verified: ${data.reference}`
                : `Saved and verified: ${data.reference}`,
        }));
        setPrivateInputRequests((current) =>
          current.map((item) =>
            item.requestId === request.requestId
              ? { ...item, status: "saved" }
              : item,
          ),
        );
      } else if (
        data?.error === "save_outcome_unknown" ||
        data?.error === "save_in_progress" ||
        response.status >= 500
      ) {
        setPrivateInputFeedback((current) => ({
          ...current,
          [request.requestId]:
            "The write outcome is unknown. Check the destination vault before starting another save.",
        }));
        setPrivateInputDrafts((current) => {
          const next = { ...current };
          delete next[request.requestId];
          return next;
        });
      } else {
        setPrivateInputFeedback((current) => ({
          ...current,
          [request.requestId]: "This request could not be fulfilled.",
        }));
      }
    } catch {
      setPrivateInputFeedback((current) => ({
        ...current,
        [request.requestId]:
          "The write outcome is unknown. Check the destination vault before starting another save.",
      }));
      setPrivateInputDrafts((current) => {
        const next = { ...current };
        delete next[request.requestId];
        return next;
      });
    } finally {
      setPrivateInputSubmitting(null);
    }
  };

  const handleFindSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    const connection = vaultConnections.find(
      (item) => item.id === findConnectionId,
    );
    if (
      !connection ||
      !connection.capabilities?.read ||
      !findReference.trim()
    ) {
      setFindStatus("error");
      setFindResult(null);
      return;
    }
    setFindStatus("searching");
    setFindResult(null);
    const requestVersion = ++findRequestVersion.current;
    const submittedReference = findReference.trim();
    try {
      const res = await fetch("/api/user/secrets/find", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          connectionId: connection.id,
          reference: submittedReference,
        }),
      });
      const data = await res.json().catch(() => null);
      if (findRequestVersion.current !== requestVersion) return;
      if (
        res.ok &&
        data?.status === "available" &&
        typeof data?.provider === "string" &&
        typeof data?.reference === "string"
      ) {
        setFindResult({ provider: data.provider, reference: data.reference });
        setFindStatus("found");
      } else {
        setFindStatus("error");
      }
    } catch {
      if (findRequestVersion.current === requestVersion) setFindStatus("error");
    }
  };

  const handleAddPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      let findSelector:
        | {
            kind: "login_lookup";
            title: string;
            username: string;
            uris: string[];
            fieldId: string;
            fieldPath?: string;
          }
        | undefined;
      if (newFindLoginEnabled) {
        const connection = vaultConnections.find(
          (candidate) => candidate.id === selectedConnectionId,
        );
        const referenceParts = newSecretId.split("#");
        let fieldId: string | undefined;
        try {
          if (referenceParts.length === 2)
            fieldId = decodeURIComponent(referenceParts[1]);
        } catch {
          fieldId = undefined;
        }
        const uris = newFindLoginUris
          .split(/\r?\n/)
          .filter((uri) => uri.trim().length > 0);
        if (
          connection?.provider !== "onepassword-connect" ||
          referenceParts.length !== 2 ||
          !referenceParts[0] ||
          !fieldId ||
          !newFindLoginTitle.trim() ||
          !newFindLoginUsername.trim() ||
          uris.length === 0 ||
          uris.length > 16 ||
          new Set(uris).size !== uris.length ||
          uris.some((uri) => uri !== uri.trim())
        )
          throw new Error("Invalid owner-pinned login locator.");
        findSelector = {
          kind: "login_lookup",
          title: newFindLoginTitle,
          username: newFindLoginUsername,
          uris,
          fieldId,
          ...(newFindLoginFieldPath.trim().length > 0
            ? { fieldPath: newFindLoginFieldPath }
            : {}),
        };
      }
      const res = await fetch("/api/user/policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alias: newAlias.toUpperCase().trim(),
          description: newDesc.trim() || "Custom alias",
          allowedDomains: newDomains.split(",").map((v) => v.trim()),
          allowedMethods: newMethods
            .split(",")
            .map((v) => v.trim().toUpperCase()),
          injectionType: newInjectionType,
          secretId: newSecretId || undefined,
          connectionId: selectedConnectionId,
          ...(findSelector ? { findSelector } : {}),
          ...(vaultConnections.some(
            (connection) =>
              connection.id === selectedConnectionId &&
              connection.provider === "onepassword-connect",
          ) &&
          (newSecretWriteCreate || newSecretWriteUpdate || newSecretWriteDelete)
            ? {
                secretWrite: {
                  create: newSecretWriteCreate,
                  update: newSecretWriteUpdate,
                  delete: newSecretWriteDelete,
                },
              }
            : {}),
        }),
      });
      if (!res.ok) throw new Error("Policy rejected");
      await refreshPolicies();
      await refreshVaultConnections();
      setNewAlias("");
      setNewDesc("");
      setNewSecretId("");
      setNewInjectionType("bearer");
      setNewFindLoginEnabled(false);
      setNewFindLoginTitle("");
      setNewFindLoginUsername("");
      setNewFindLoginUris("");
      setNewFindLoginFieldPath("");
      setNewSecretWriteCreate(false);
      setNewSecretWriteUpdate(false);
      setNewSecretWriteDelete(false);
    } catch {
      setDashboardNotice(
        "Policy was not saved. Check your session and policy fields.",
      );
    }
  };

  const handleUpdateLoginLocator = async (e: React.FormEvent) => {
    e.preventDefault();
    const policy = policies.find((item) => item.alias === editingLoginAlias);
    if (!policy) return;
    try {
      let findSelector: Record<string, unknown> | null = null;
      if (editLoginEnabled) {
        const referenceParts = (policy.secretId || "").split("#");
        let fieldId = "";
        try {
          if (referenceParts.length === 2)
            fieldId = decodeURIComponent(referenceParts[1]);
        } catch {
          fieldId = "";
        }
        const uris = editLoginUris
          .split(/\r?\n/)
          .filter((uri) => uri.trim().length > 0);
        if (
          !fieldId ||
          !editLoginTitle.trim() ||
          !editLoginUsername.trim() ||
          uris.length === 0 ||
          uris.length > 16 ||
          new Set(uris).size !== uris.length ||
          uris.some((uri) => uri !== uri.trim())
        )
          throw new Error("Invalid owner-pinned login locator.");
        findSelector = {
          kind: "login_lookup",
          title: editLoginTitle,
          username: editLoginUsername,
          uris,
          fieldId,
          ...(editLoginFieldPath.trim().length > 0
            ? { fieldPath: editLoginFieldPath }
            : {}),
        };
      }
      const res = await fetch("/api/user/policies", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias: policy.alias, findSelector }),
      });
      if (!res.ok) throw new Error("Locator update rejected");
      await refreshPolicies();
      setEditingLoginAlias(null);
      setDashboardNotice(
        "Login lookup settings saved. Agents with existing grants must consent again to the updated policy.",
      );
    } catch {
      setDashboardNotice(
        "Login lookup settings were not saved. Check the connection and locator fields, then retry.",
      );
    }
  };

  const handleApproveExecutor = async (e: React.FormEvent) => {
    e.preventDefault();
    setExecutorFeedback(null);
    try {
      const parsed = JSON.parse(executorApproval) as {
        identity?: Record<string, unknown>;
      } & Record<string, unknown>;
      const identity =
        parsed.identity && typeof parsed.identity === "object"
          ? parsed.identity
          : parsed;
      const response = await fetch("/api/executor/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          executorId: identity.executorId,
          publicJwk: identity.publicJwk,
          createdAt: identity.createdAt,
        }),
      });
      const data = await response.json().catch(() => null);
      if (!response.ok || data?.status !== "enrolled")
        throw new Error("Executor approval failed.");
      setExecutorApproval("");
      setExecutorFeedback("Executor public identity approved.");
      await refreshExecutorState();
    } catch {
      setExecutorFeedback(
        "The pasted public identity was not approved. Paste the exact JSON printed by agentsecret browser identity; private key fields are refused.",
      );
    }
  };

  const handleIssueBrowserGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    setGrantFeedback(null);
    try {
      const response = await fetch("/api/executor/grants", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          executorId: grantExecutorId,
          alias: grantAlias,
          origin: grantOrigin.trim(),
          kinds: grantActions
            .split(",")
            .map((value) => value.trim())
            .filter(Boolean),
          fieldSelector: grantSelector,
          expiresIn: 60,
        }),
      });
      const data = await response.json().catch(() => null);
      if (!response.ok || typeof data?.grantId !== "string")
        throw new Error("Grant issue failed.");
      setGrantFeedback(
        `Issued ${data.grantId}. It is visible to the enrolled executor and expires in 60 seconds.`,
      );
      await refreshExecutorState();
    } catch {
      setGrantFeedback(
        "The grant was not issued. Check the executor, alias, exact HTTPS origin, allowed actions and field selector.",
      );
    }
  };

  const handleRevokeBrowserGrant = async (grantId: string) => {
    setGrantFeedback(null);
    const response = await fetch("/api/executor/grants/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ grantId }),
    });
    if (!response.ok) {
      setGrantFeedback("The grant could not be revoked.");
      return;
    }
    setGrantFeedback("Grant revoked. Any unredeemed copy is now unusable.");
    await refreshExecutorState();
  };

  const handleRevokeExecutor = async (executorId: string) => {
    setExecutorFeedback(null);
    const response = await fetch("/api/executor/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ executorId }),
    });
    if (!response.ok) {
      setExecutorFeedback("The executor could not be revoked.");
      return;
    }
    setExecutorFeedback(
      "Executor revoked with its outstanding grants. Re-enroll only after restoring the trusted device.",
    );
    await refreshExecutorState();
  };

  const runSimulation = async () => {
    if (!user || !policies.some((p) => p.alias === simAlias)) return;
    setSimLoading(true);
    setSimResult(null);
    try {
      const res = await fetch("/proxy", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          secret_alias: simAlias,
          url: simUrl,
          method: simMethod,
        }),
      });
      const data = await res.json();
      setSimResult(
        res.ok
          ? { ...data, status: data.status ?? res.status }
          : {
              status: res.status,
              error:
                typeof data.error === "string"
                  ? data.error
                  : "Broker request failed.",
            },
      );
    } catch {
      setSimResult({
        error: "Broker request failed. No simulated success was substituted.",
      });
    } finally {
      setSimLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#ffffff",
        color: "#0f172a",
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif',
      }}
    >
      {/* ─────────────────────────────────────────────────────────────
          SOCIAL LOGIN MODAL
         ───────────────────────────────────────────────────────────── */}
      {showAuthModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(15, 23, 42, 0.45)",
            backdropFilter: "blur(3px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 100,
          }}
        >
          <div
            style={{
              background: "#ffffff",
              borderRadius: "12px",
              border: "1px solid #e2e8f0",
              padding: "28px",
              width: "380px",
              boxShadow:
                "0 20px 25px -5px rgba(0,0,0,0.1), 0 8px 10px -6px rgba(0,0,0,0.1)",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                marginBottom: "16px",
              }}
            >
              <div>
                <h3
                  style={{
                    fontSize: "17px",
                    fontWeight: 800,
                    color: "#0f172a",
                  }}
                >
                  Sign in to AgentSecret
                </h3>
                <p
                  style={{
                    fontSize: "12px",
                    color: "#64748b",
                    marginTop: "3px",
                  }}
                >
                  Authenticate to manage secret vaults &amp; policies.
                </p>
              </div>
              <button
                onClick={() => setShowAuthModal(false)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#94a3b8",
                  fontSize: "20px",
                  cursor: "pointer",
                  lineHeight: 1,
                }}
              >
                ×
              </button>
            </div>

            <div
              style={{ display: "flex", flexDirection: "column", gap: "10px" }}
            >
              <button
                onClick={() => startSocialLogin("github")}
                style={{
                  width: "100%",
                  background: "#0f172a",
                  color: "#ffffff",
                  border: "none",
                  padding: "11px 16px",
                  borderRadius: "6px",
                  fontSize: "13px",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "10px",
                }}
                className="btn-tactile"
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="currentColor"
                >
                  <path
                    fillRule="evenodd"
                    clipRule="evenodd"
                    d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                  />
                </svg>
                Continue with GitHub
              </button>

              <button
                onClick={() => startSocialLogin("google")}
                style={{
                  width: "100%",
                  background: "#ffffff",
                  color: "#0f172a",
                  border: "1px solid #cbd5e1",
                  padding: "11px 16px",
                  borderRadius: "6px",
                  fontSize: "13px",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "10px",
                }}
                className="btn-tactile"
              >
                <svg width="16" height="16" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                Continue with Google
              </button>
            </div>
          </div>
        </div>
      )}

      <div
        style={{
          padding: "10px 24px",
          fontSize: 12,
          background: "#f1f5f9",
          color: "#334155",
        }}
      >
        Strict broker profile: Bitwarden and 1Password service accounts, with
        owner-approved local companions for password-manager stores. Agent
        credentials require DPoP. Billing is disabled.
        {user && <span> Account: {user.id}. </span>}
      </div>

      {view === "dashboard" &&
        user &&
        user.onboarding &&
        !user.onboarding.complete && (
          <form
            onSubmit={handleOnboarding}
            style={{
              margin: "0 auto",
              maxWidth: "1160px",
              padding: "14px 24px",
              display: "flex",
              flexWrap: "wrap",
              gap: "10px",
              alignItems: "center",
              background: "#eff6ff",
              borderBottom: "1px solid #dbeafe",
              color: "#1e3a8a",
              fontSize: 13,
            }}
          >
            <strong>Finish setting up your account.</strong>
            <span>
              Pick the display name this account uses. No email confirmation is
              required.
            </span>
            <input
              aria-label="Display name"
              value={onboardingName}
              onChange={(e) => setOnboardingName(e.target.value)}
              placeholder="Display name"
              style={{
                padding: "7px 10px",
                borderRadius: "6px",
                border: "1px solid #93c5fd",
                fontSize: 13,
              }}
            />
            <button
              type="submit"
              style={{
                padding: "7px 12px",
                borderRadius: "6px",
                border: "none",
                background: "#1d4ed8",
                color: "#ffffff",
                fontWeight: 600,
                fontSize: 13,
                cursor: "pointer",
              }}
            >
              Save
            </button>
            {onboardingStatus === "error" && (
              <span role="alert" style={{ color: "#b91c1c" }}>
                Could not save your display name. Retry.
              </span>
            )}
          </form>
        )}

      {/* ─────────────────────────────────────────────────────────────
          MODE 1: SALES FUNNEL PUBLIC LANDING PAGE
         ───────────────────────────────────────────────────────────── */}
      {view === "landing" && (
        <div
          className="white-minimal-grid"
          style={{
            minHeight: "100vh",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* Clean, Uncluttered Top Navbar */}
          <header
            style={{
              borderBottom: "1px solid #eaecf0",
              background: "rgba(255, 255, 255, 0.95)",
              backdropFilter: "blur(8px)",
              position: "sticky",
              top: 0,
              zIndex: 40,
            }}
          >
            <div
              style={{
                maxWidth: "1160px",
                margin: "0 auto",
                padding: "16px 24px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              {/* Brand Logo */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  cursor: "pointer",
                }}
                onClick={() => setView("landing")}
              >
                <div
                  style={{
                    background: "#0f172a",
                    color: "#ffffff",
                    padding: "7px",
                    borderRadius: "7px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <Shield size={18} strokeWidth={2.4} />
                </div>
                <span
                  style={{
                    fontSize: "16px",
                    fontWeight: 800,
                    letterSpacing: "-0.03em",
                    color: "#0f172a",
                  }}
                >
                  AgentSecret
                </span>
              </div>

              {/* Subdued Funnel Anchor Links */}
              <nav
                style={{ display: "flex", alignItems: "center", gap: "28px" }}
              >
                <a
                  href="#how-it-works"
                  style={{
                    fontSize: "13px",
                    color: "#64748b",
                    textDecoration: "none",
                    fontWeight: 500,
                  }}
                >
                  How It Works
                </a>
                <a
                  href="#how-it-works"
                  style={{
                    fontSize: "13px",
                    color: "#64748b",
                    textDecoration: "none",
                    fontWeight: 500,
                  }}
                >
                  Broker Illustration
                </a>
                <a
                  href="#integrations"
                  style={{
                    fontSize: "13px",
                    color: "#64748b",
                    textDecoration: "none",
                    fontWeight: 500,
                  }}
                >
                  Integrations
                </a>
                <a
                  href="#pricing"
                  style={{
                    fontSize: "13px",
                    color: "#64748b",
                    textDecoration: "none",
                    fontWeight: 500,
                  }}
                >
                  Pricing
                </a>
              </nav>

              {/* Primary Conversion Actions */}
              <div
                style={{ display: "flex", alignItems: "center", gap: "10px" }}
              >
                <button
                  onClick={() => setShowAuthModal(true)}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#0f172a",
                    fontSize: "13px",
                    fontWeight: 600,
                    cursor: "pointer",
                    padding: "6px 12px",
                  }}
                >
                  Sign in
                </button>
                <button
                  onClick={() => {
                    if (user) {
                      setView("dashboard");
                    } else {
                      setShowAuthModal(true);
                    }
                  }}
                  style={{
                    background: "#0f172a",
                    color: "#ffffff",
                    border: "none",
                    padding: "8px 16px",
                    borderRadius: "6px",
                    fontSize: "13px",
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                  className="btn-tactile"
                >
                  Get Started Free
                </button>
              </div>
            </div>
          </header>

          {/* Sales Funnel Hero Section */}
          <section
            style={{
              maxWidth: "1080px",
              margin: "0 auto",
              padding: "80px 24px 60px 24px",
              textAlign: "center",
            }}
          >
            {/* Status Pill */}
            <div
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "8px",
                background: "#ecfdf5",
                border: "1px solid #a7f3d0",
                borderRadius: "20px",
                padding: "4px 14px",
                marginBottom: "24px",
              }}
            >
              <div
                style={{
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: "#059669",
                }}
              />
              <span
                style={{
                  fontSize: "11px",
                  fontFamily: "monospace",
                  color: "#059669",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  fontWeight: 700,
                }}
              >
                Policy-bound secret broker
              </span>
            </div>

            {/* Magnetic Value Proposition Headline */}
            <h1
              style={{
                fontSize: "54px",
                fontWeight: 800,
                letterSpacing: "-0.04em",
                lineHeight: 1.12,
                color: "#0f172a",
                maxWidth: "880px",
                margin: "0 auto 20px auto",
              }}
            >
              Give agents approved API access through secret aliases.
            </h1>

            {/* Acute Pain Point Subhead */}
            <p
              style={{
                fontSize: "19px",
                color: "#475569",
                lineHeight: 1.6,
                maxWidth: "740px",
                margin: "0 auto 36px auto",
              }}
            >
              AgentSecret uses <strong>Bitwarden Secrets Manager</strong>,{" "}
              <strong>1Password service accounts</strong>, or an owner-bound
              local password-manager companion. Agents receive scoped results
              through aliases. The operator, broker, device, companion, and
              approved upstream remain trust boundaries.
            </p>

            {/* High-Converting Funnel CTAs */}
            <div
              style={{
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                gap: "14px",
                flexWrap: "wrap",
                marginBottom: "40px",
              }}
            >
              <button
                onClick={() => {
                  if (user) {
                    setView("dashboard");
                  } else {
                    setShowAuthModal(true);
                  }
                }}
                style={{
                  background: "#0f172a",
                  color: "#ffffff",
                  border: "none",
                  padding: "14px 28px",
                  borderRadius: "6px",
                  fontSize: "15px",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                }}
                className="btn-tactile"
              >
                Start Securing Agents Free <ArrowRight size={17} />
              </button>

              <a
                href="#how-it-works"
                style={{
                  background: "#ffffff",
                  color: "#0f172a",
                  border: "1px solid #cbd5e1",
                  padding: "14px 22px",
                  borderRadius: "6px",
                  fontSize: "15px",
                  fontWeight: 600,
                  textDecoration: "none",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                }}
                className="btn-tactile"
              >
                <Play size={15} color="#2563eb" /> See Broker Illustration
              </a>
            </div>

            <div style={{ fontSize: "12px", color: "#64748b" }}>
              Self-hosted · Operator-configured monthly allowance
            </div>

            {/* Architecture Metrics Grid */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
                gap: "14px",
                marginTop: "54px",
                textAlign: "left",
              }}
            >
              <div
                style={{
                  background: "#ffffff",
                  border: "1px solid #e2e8f0",
                  borderRadius: "8px",
                  padding: "20px",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
                }}
              >
                <div
                  style={{
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                    color: "#64748b",
                    fontWeight: 600,
                  }}
                >
                  Credential delivery
                </div>
                <div
                  style={{
                    fontSize: "28px",
                    fontWeight: 800,
                    fontFamily: "monospace",
                    color: "#059669",
                    margin: "4px 0",
                  }}
                >
                  Brokered
                </div>
                <div style={{ fontSize: "11px", color: "#64748b" }}>
                  Isolated V8 edge memory injection
                </div>
              </div>

              <div
                style={{
                  background: "#ffffff",
                  border: "1px solid #e2e8f0",
                  borderRadius: "8px",
                  padding: "20px",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
                }}
              >
                <div
                  style={{
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                    color: "#64748b",
                    fontWeight: 600,
                  }}
                >
                  Request execution
                </div>
                <div
                  style={{
                    fontSize: "28px",
                    fontWeight: 800,
                    fontFamily: "monospace",
                    color: "#2563eb",
                    margin: "4px 0",
                  }}
                >
                  Bounded IO
                </div>
                <div style={{ fontSize: "11px", color: "#64748b" }}>
                  Global edge worker distribution
                </div>
              </div>

              <div
                style={{
                  background: "#ffffff",
                  border: "1px solid #e2e8f0",
                  borderRadius: "8px",
                  padding: "20px",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
                }}
              >
                <div
                  style={{
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                    color: "#64748b",
                    fontWeight: 600,
                  }}
                >
                  Firewall Protection
                </div>
                <div
                  style={{
                    fontSize: "28px",
                    fontWeight: 800,
                    fontFamily: "monospace",
                    color: "#4f46e5",
                    margin: "4px 0",
                  }}
                >
                  Allowlisted
                </div>
                <div style={{ fontSize: "11px", color: "#64748b" }}>
                  HTTPS domain, method, and path policies
                </div>
              </div>

              <div
                style={{
                  background: "#ffffff",
                  border: "1px solid #e2e8f0",
                  borderRadius: "8px",
                  padding: "20px",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
                }}
              >
                <div
                  style={{
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                    color: "#64748b",
                    fontWeight: 600,
                  }}
                >
                  Database &amp; Vaults
                </div>
                <div
                  style={{
                    fontSize: "28px",
                    fontWeight: 800,
                    fontFamily: "monospace",
                    color: "#0f172a",
                    margin: "4px 0",
                  }}
                >
                  SQLite DO
                </div>
                <div style={{ fontSize: "11px", color: "#64748b" }}>
                  Bitwarden / 1Password service account
                </div>
              </div>
            </div>
          </section>

          {/* ─────────────────────────────────────────────────────────────
              FUNNEL SECTION 3: HOW IT WORKS IN 3 STEPS
             ───────────────────────────────────────────────────────────── */}
          <section
            id="how-it-works"
            style={{
              maxWidth: "1080px",
              margin: "50px auto",
              padding: "0 24px",
              width: "100%",
            }}
          >
            <div style={{ textAlign: "center", marginBottom: "40px" }}>
              <div
                style={{
                  fontSize: "11px",
                  fontFamily: "monospace",
                  color: "#2563eb",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  marginBottom: "8px",
                }}
              >
                Simple 3-Step Architecture
              </div>
              <h2
                style={{
                  fontSize: "32px",
                  fontWeight: 800,
                  letterSpacing: "-0.03em",
                  color: "#0f172a",
                }}
              >
                How AgentSecret Works
              </h2>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: "20px",
              }}
            >
              <div
                style={{
                  background: "#ffffff",
                  border: "1px solid #e2e8f0",
                  borderRadius: "8px",
                  padding: "24px",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
                }}
              >
                <div
                  style={{
                    width: "32px",
                    height: "32px",
                    borderRadius: "50%",
                    background: "#eff6ff",
                    color: "#2563eb",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 800,
                    fontSize: "14px",
                    marginBottom: "14px",
                  }}
                >
                  1
                </div>
                <h4
                  style={{
                    fontSize: "16px",
                    fontWeight: 700,
                    color: "#0f172a",
                    marginBottom: "8px",
                  }}
                >
                  Connect Your Vault
                </h4>
                <p
                  style={{
                    fontSize: "13px",
                    color: "#64748b",
                    lineHeight: 1.5,
                  }}
                >
                  Connect Bitwarden Secrets Manager directly, or bind a
                  Bitwarden Password Manager, 1Password service account, or
                  LastPass companion locally. The broker encrypts cloud
                  connection metadata at rest with AES-256-GCM.
                </p>
              </div>

              <div
                style={{
                  background: "#ffffff",
                  border: "1px solid #e2e8f0",
                  borderRadius: "8px",
                  padding: "24px",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
                }}
              >
                <div
                  style={{
                    width: "32px",
                    height: "32px",
                    borderRadius: "50%",
                    background: "#ecfdf5",
                    color: "#059669",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 800,
                    fontSize: "14px",
                    marginBottom: "14px",
                  }}
                >
                  2
                </div>
                <h4
                  style={{
                    fontSize: "16px",
                    fontWeight: 700,
                    color: "#0f172a",
                    marginBottom: "8px",
                  }}
                >
                  Define Whitelist Policies
                </h4>
                <p
                  style={{
                    fontSize: "13px",
                    color: "#64748b",
                    lineHeight: 1.5,
                  }}
                >
                  Map secret aliases to strict target domains and HTTP methods
                  (e.g. <code>GITHUB_API</code> can only communicate with{" "}
                  <code>api.github.com</code>).
                </p>
              </div>

              <div
                style={{
                  background: "#ffffff",
                  border: "1px solid #e2e8f0",
                  borderRadius: "8px",
                  padding: "24px",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
                }}
              >
                <div
                  style={{
                    width: "32px",
                    height: "32px",
                    borderRadius: "50%",
                    background: "#f5f3ff",
                    color: "#7c3aed",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 800,
                    fontSize: "14px",
                    marginBottom: "14px",
                  }}
                >
                  3
                </div>
                <h4
                  style={{
                    fontSize: "16px",
                    fontWeight: 700,
                    color: "#0f172a",
                    marginBottom: "8px",
                  }}
                >
                  Point Your Agents
                </h4>
                <p
                  style={{
                    fontSize: "13px",
                    color: "#64748b",
                    lineHeight: 1.5,
                  }}
                >
                  Use the authenticated companion with an agent that supports
                  local stdio MCP. The cloud returns bounded API results; it
                  does not execute a native command on your device.
                </p>
              </div>
            </div>
          </section>

          {/* ─────────────────────────────────────────────────────────────
              FUNNEL SECTION 4: INTEGRATIONS
             ───────────────────────────────────────────────────────────── */}
          <section
            id="integrations"
            style={{
              maxWidth: "1080px",
              margin: "40px auto",
              padding: "24px",
              width: "100%",
              border: "1px solid #e2e8f0",
              borderRadius: "8px",
            }}
          >
            <h2>Connect your agent</h2>
            <p>
              Authenticate the companion once, then use a local stdio MCP
              configuration. The companion signs each cloud request with its own
              device key.
            </p>
            <pre
              style={{ overflowX: "auto" }}
            >{`agentsecret login --server ${window.location.origin} --aliases API_TOKEN
agentsecret request --alias API_TOKEN --url https://api.example.com/status`}</pre>
            <pre style={{ overflowX: "auto" }}>
              {JSON.stringify(
                {
                  mcpServers: {
                    agentsecret: {
                      command: "agentsecret",
                      args: ["mcp", "--server", window.location.origin],
                    },
                  },
                },
                null,
                2,
              )}
            </pre>
            <button
              onClick={() =>
                copyToClipboard(
                  JSON.stringify(
                    {
                      mcpServers: {
                        agentsecret: {
                          command: "agentsecret",
                          args: ["mcp", "--server", window.location.origin],
                        },
                      },
                    },
                    null,
                    2,
                  ),
                  "landing-mcp",
                )
              }
            >
              {copiedSnippet === "landing-mcp"
                ? "Copied"
                : "Copy MCP configuration"}
            </button>
            <p>
              Direct remote MCP clients must support PKCE, DPoP, and a
              registered callback. Host support must be verified. OpenAPI
              Actions and legacy SSE are unavailable in this profile.
            </p>
          </section>

          {/* ─────────────────────────────────────────────────────────────
              FUNNEL SECTION 5: PRICING (Clean, Transparent, No Slop)
             ───────────────────────────────────────────────────────────── */}
          <section
            id="pricing"
            style={{
              maxWidth: "1080px",
              margin: "50px auto",
              padding: "24px",
              width: "100%",
              border: "1px solid #e2e8f0",
              borderRadius: "8px",
            }}
          >
            <h2>Self-hosted operation</h2>
            <p>
              This profile has no paid plans or checkout. The operator
              configures a monthly tenant allowance; Cloudflare and
              vault-provider costs are separate.
            </p>
          </section>

          {/* ─────────────────────────────────────────────────────────────
              FUNNEL SECTION 6: FAQ ACCORDION
             ───────────────────────────────────────────────────────────── */}
          <section
            style={{
              maxWidth: "820px",
              margin: "40px auto 70px auto",
              padding: "0 24px",
              width: "100%",
            }}
          >
            <h3
              style={{
                fontSize: "24px",
                fontWeight: 800,
                textAlign: "center",
                marginBottom: "24px",
                color: "#0f172a",
              }}
            >
              Frequently Asked Questions
            </h3>

            <div
              style={{ display: "flex", flexDirection: "column", gap: "10px" }}
            >
              {[
                {
                  q: "Does AgentSecret ever store or log my raw API keys in plain text?",
                  a: "The browser sends vault credentials over HTTPS to the trusted broker, which encrypts them at rest with a separate AES-GCM key. Upstream keys exist in broker memory. Logs exclude credential values; reflected known strings are scrubbed as defense in depth.",
                },
                {
                  q: "What is the difference between Bitwarden Secrets Manager and Bitwarden Password Manager?",
                  a: "Bitwarden Secrets Manager uses a machine-account token in the broker. Bitwarden Password Manager stays behind an owner-bound local companion and is not unlocked in the cloud.",
                },
                {
                  q: "How does AgentSecret prevent the LLM from leaking credentials?",
                  a: "The API exposes aliases and approved requests instead of raw credentials. Scope and destination policies limit what a compromised agent can ask for. The approved upstream is trusted; sanitization cannot stop every possible encoding of a secret by a malicious upstream.",
                },
                {
                  q: "Can I self-host AgentSecret or run on-premise?",
                  a: "Deploy the Worker and SQLite Durable Object to your own Cloudflare account after configuring keys and identity policy. The local test runtime uses workerd. A generic on-premise deployment is not supplied.",
                },
              ].map((faq, i) => (
                <div
                  key={i}
                  style={{
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    background: "#ffffff",
                    overflow: "hidden",
                  }}
                >
                  <button
                    onClick={() => setOpenFaq(openFaq === i ? null : i)}
                    style={{
                      width: "100%",
                      padding: "16px 20px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      background: "transparent",
                      border: "none",
                      cursor: "pointer",
                      textAlign: "left",
                      fontWeight: 700,
                      fontSize: "14px",
                      color: "#0f172a",
                    }}
                  >
                    <span>{faq.q}</span>
                    <span style={{ fontSize: "18px", color: "#94a3b8" }}>
                      {openFaq === i ? "−" : "+"}
                    </span>
                  </button>
                  {openFaq === i && (
                    <div
                      style={{
                        padding: "0 20px 16px 20px",
                        fontSize: "13px",
                        color: "#475569",
                        lineHeight: 1.6,
                      }}
                    >
                      {faq.a}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>

          {/* Footer */}
          <footer
            style={{
              borderTop: "1px solid #eaecf0",
              padding: "32px 24px",
              textAlign: "center",
              fontSize: "12px",
              color: "#64748b",
              background: "#ffffff",
              marginTop: "auto",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "center",
                gap: "20px",
                marginBottom: "12px",
              }}
            >
              <span
                style={{ cursor: "pointer", color: "#0f172a" }}
                onClick={() => setView("landing")}
              >
                Home
              </span>
              <span
                style={{ cursor: "pointer", color: "#0f172a" }}
                onClick={() => {
                  setView("dashboard");
                  setActiveTab("oauth");
                }}
              >
                Companion authorization
              </span>
              <a
                href="/.well-known/oauth-protected-resource"
                target="_blank"
                rel="noreferrer"
                style={{ color: "#64748b", textDecoration: "none" }}
              >
                Broker metadata
              </a>
              <a
                href="/privacy.html"
                style={{ color: "#64748b", textDecoration: "none" }}
              >
                Privacy
              </a>
              <a
                href="/source.tar.gz"
                download
                style={{ color: "#64748b", textDecoration: "none" }}
              >
                Corresponding Source
              </a>
              <a
                href="/source-revision.json"
                target="_blank"
                rel="noreferrer"
                style={{ color: "#64748b", textDecoration: "none" }}
              >
                Source revision
              </a>
              <a
                href="https://agentsecret.astronlab.com/health"
                target="_blank"
                rel="noreferrer"
                style={{ color: "#64748b", textDecoration: "none" }}
              >
                Health Check
              </a>
            </div>
            <div>AgentSecret by AstronLab · Policy-bound broker access</div>
          </footer>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          MODE 2: AUTHENTICATED OPERATOR DASHBOARD
          (Left-Sided Dashboard Menus - Dribbble SaaS Standard)
         ───────────────────────────────────────────────────────────── */}
      {view === "dashboard" && (
        <div
          style={{ display: "flex", minHeight: "100vh", background: "#f8fafc" }}
        >
          {/* ─────────────────────────────────────────────────────────
              LEFT-SIDED DASHBOARD SIDEBAR (Dribbble Standard)
             ───────────────────────────────────────────────────────── */}
          <aside
            style={{
              width: "250px",
              background: "#ffffff",
              borderRight: "1px solid #eaecf0",
              display: "flex",
              flexDirection: "column",
              flexShrink: 0,
              position: "sticky",
              top: 0,
              height: "100vh",
            }}
          >
            {/* Sidebar Header & Brand */}
            <div
              style={{
                padding: "18px 20px",
                borderBottom: "1px solid #f1f5f9",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "9px",
                  cursor: "pointer",
                }}
                onClick={() => setView("landing")}
              >
                <div
                  style={{
                    background: "#0f172a",
                    color: "#ffffff",
                    padding: "6px",
                    borderRadius: "6px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <Shield size={16} strokeWidth={2.4} />
                </div>
                <div>
                  <div
                    style={{
                      fontSize: "14px",
                      fontWeight: 800,
                      letterSpacing: "-0.02em",
                      color: "#0f172a",
                    }}
                  >
                    AgentSecret
                  </div>
                  <div
                    style={{
                      fontSize: "10px",
                      color: "#64748b",
                      textTransform: "uppercase",
                      letterSpacing: "0.04em",
                      fontFamily: "monospace",
                    }}
                  >
                    {window.location.origin}
                  </div>
                </div>
              </div>
            </div>

            <div
              style={{
                display: "flex",
                gap: 12,
                padding: "10px 20px",
                fontSize: 12,
              }}
            >
              <a href="/source.tar.gz" download>
                Corresponding Source
              </a>
              <a href="/source-revision.json" target="_blank" rel="noreferrer">
                Source revision
              </a>
            </div>

            {/* Workspace Selector Pill */}
            <div style={{ padding: "12px 16px" }}>
              <div
                style={{
                  background: "#f1f5f9",
                  borderRadius: "6px",
                  padding: "8px 12px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <div
                    style={{
                      width: "7px",
                      height: "7px",
                      borderRadius: "50%",
                      background: "#059669",
                    }}
                  />
                  <span
                    style={{
                      fontSize: "12px",
                      fontWeight: 700,
                      color: "#0f172a",
                    }}
                  >
                    {user?.id || "Not signed in"}
                  </span>
                </div>
                <span
                  style={{
                    fontSize: "10px",
                    background: "#ffffff",
                    border: "1px solid #cbd5e1",
                    padding: "1px 5px",
                    borderRadius: "3px",
                    fontWeight: 600,
                    color: "#475569",
                  }}
                >
                  {user?.plan?.toUpperCase() || "UNAUTHENTICATED"}
                </span>
              </div>
            </div>

            {/* Navigation Menus */}
            <div
              style={{
                padding: "6px 12px",
                flex: 1,
                overflowY: "auto",
                display: "flex",
                flexDirection: "column",
                gap: "3px",
              }}
            >
              <div
                style={{
                  fontSize: "10px",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  color: "#94a3b8",
                  padding: "6px 10px",
                }}
              >
                Workspace
              </div>

              {[
                {
                  id: "overview",
                  label: "Overview",
                  icon: <Layers size={15} />,
                },
                {
                  id: "vaults",
                  label: "Vault Connections",
                  icon: <Database size={15} />,
                },
                {
                  id: "secrets",
                  label: "Secrets",
                  icon: <Key size={15} />,
                },
                {
                  id: "policies",
                  label: "Secret Policies",
                  icon: <Globe size={15} />,
                },
                {
                  id: "simulator",
                  label: "Egress Simulator",
                  icon: <Play size={15} />,
                },
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as DashboardTab)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    width: "100%",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12.5px",
                    fontWeight: activeTab === item.id ? 700 : 500,
                    color: activeTab === item.id ? "#0f172a" : "#475569",
                    background:
                      activeTab === item.id ? "#f1f5f9" : "transparent",
                    border: "none",
                    cursor: "pointer",
                    textAlign: "left",
                  }}
                  className="btn-tactile"
                >
                  <span
                    style={{
                      color: activeTab === item.id ? "#0f172a" : "#64748b",
                    }}
                  >
                    {item.icon}
                  </span>
                  {item.label}
                </button>
              ))}

              <div
                style={{
                  fontSize: "10px",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  color: "#94a3b8",
                  padding: "12px 10px 6px 10px",
                }}
              >
                Security &amp; Agents
              </div>

              {[
                {
                  id: "oauth",
                  label: "Companion authorization",
                  icon: <Key size={15} />,
                },
                { id: "audit", label: "Audit Trail", icon: <List size={15} /> },
                {
                  id: "integrations",
                  label: "Agent Setup",
                  icon: <Code2 size={15} />,
                },
              ].map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as DashboardTab)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    width: "100%",
                    padding: "8px 12px",
                    borderRadius: "6px",
                    fontSize: "12.5px",
                    fontWeight: activeTab === item.id ? 700 : 500,
                    color: activeTab === item.id ? "#0f172a" : "#475569",
                    background:
                      activeTab === item.id ? "#f1f5f9" : "transparent",
                    border: "none",
                    cursor: "pointer",
                    textAlign: "left",
                  }}
                  className="btn-tactile"
                >
                  <span
                    style={{
                      color: activeTab === item.id ? "#0f172a" : "#64748b",
                    }}
                  >
                    {item.icon}
                  </span>
                  {item.label}
                </button>
              ))}
            </div>

            {/* Sidebar Bottom: User Profile & Public Site Link */}
            <div
              style={{
                padding: "14px 16px",
                borderTop: "1px solid #eaecf0",
                background: "#fafbfc",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: "10px",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "9px" }}
                >
                  <img
                    src={
                      user?.avatarUrl ||
                      "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80"
                    }
                    alt="User"
                    style={{
                      width: "28px",
                      height: "28px",
                      borderRadius: "50%",
                      objectFit: "cover",
                    }}
                  />
                  <div>
                    <div
                      style={{
                        fontSize: "12px",
                        fontWeight: 700,
                        color: "#0f172a",
                        lineHeight: 1.2,
                      }}
                    >
                      {user?.name || "Developer"}
                    </div>
                    <div style={{ fontSize: "10px", color: "#64748b" }}>
                      {user?.email || "dev@astronlab.com"}
                    </div>
                  </div>
                </div>

                <button
                  onClick={handleLogout}
                  title="Sign Out"
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#94a3b8",
                    cursor: "pointer",
                    padding: "4px",
                  }}
                >
                  <LogOut size={14} />
                </button>
              </div>

              <button
                onClick={() => setView("landing")}
                style={{
                  width: "100%",
                  background: "#ffffff",
                  border: "1px solid #d1d5db",
                  color: "#475569",
                  padding: "6px 10px",
                  borderRadius: "5px",
                  fontSize: "11px",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "6px",
                }}
                className="btn-tactile"
              >
                ← Back to Public Site
              </button>
            </div>
          </aside>

          {/* ─────────────────────────────────────────────────────────
              MAIN DASHBOARD CONTENT AREA
             ───────────────────────────────────────────────────────── */}
          <main
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              minWidth: 0,
              height: "100vh",
              overflowY: "auto",
            }}
          >
            {/* Top Workspace Header & Breadcrumbs */}
            <div
              style={{
                background: "#ffffff",
                borderBottom: "1px solid #eaecf0",
                padding: "14px 28px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  fontSize: "13px",
                }}
              >
                <span style={{ color: "#64748b" }}>Workspace</span>
                <ChevronRight size={14} color="#94a3b8" />
                <span
                  style={{
                    fontWeight: 700,
                    color: "#0f172a",
                    textTransform: "capitalize",
                  }}
                >
                  {activeTab.replace(/([A-Z])/g, " $1")}
                </span>
              </div>

              <div
                style={{ display: "flex", alignItems: "center", gap: "12px" }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    fontSize: "11px",
                    color: "#059669",
                    background: "#ecfdf5",
                    padding: "4px 10px",
                    borderRadius: "4px",
                    border: "1px solid #a7f3d0",
                    fontWeight: 600,
                  }}
                >
                  <div
                    style={{
                      width: "6px",
                      height: "6px",
                      borderRadius: "50%",
                      background: "#059669",
                    }}
                  />
                  {user ? "Account session" : "Not signed in"}
                </div>

                <button
                  onClick={() => setActiveTab("overview")}
                  style={{
                    background: "#0f172a",
                    color: "#ffffff",
                    border: "none",
                    padding: "6px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    fontWeight: 600,
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                  }}
                  className="btn-tactile"
                >
                  <Zap size={13} fill="#ffffff" /> Allowance
                </button>
              </div>
            </div>

            {/* Notification Banner if present */}
            {dashboardNotice && (
              <div
                role="alert"
                style={{
                  background: "#fff1f2",
                  borderBottom: "1px solid #fecdd3",
                  color: "#9f1239",
                  padding: "10px 28px",
                  fontSize: "12px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <CheckCircle size={15} /> {dashboardNotice}
                </div>
                <button
                  onClick={() => setDashboardNotice(null)}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#9f1239",
                    cursor: "pointer",
                    fontWeight: 700,
                  }}
                >
                  ×
                </button>
              </div>
            )}

            {/* Content Container */}
            <div
              style={{
                padding: "28px",
                maxWidth: "1000px",
                display: "flex",
                flexDirection: "column",
                gap: "20px",
              }}
            >
              <button
                onClick={async () => {
                  try {
                    const res = await fetch("/api/user/revoke", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: "{}",
                    });
                    if (!res.ok) throw new Error();
                    setUser(null);
                    clearVaultCredentialDraft();
                    setView("landing");
                    setDashboardNotice(
                      "Tenant sessions and outstanding grants revoked. Sign in again.",
                    );
                  } catch {
                    setDashboardNotice(
                      "Revocation failed. Retry from an authenticated customer session.",
                    );
                  }
                }}
              >
                Revoke all tenant sessions and pending grants
              </button>
              {/* TAB: OVERVIEW */}
              {activeTab === "overview" && (
                <>
                  {/* Gauge Cards */}
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        "repeat(auto-fit, minmax(220px, 1fr))",
                      gap: "14px",
                    }}
                  >
                    <div
                      style={{
                        background: "#ffffff",
                        border: "1px solid #e2e8f0",
                        borderRadius: "8px",
                        padding: "18px",
                        boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.04em",
                          color: "#64748b",
                          fontWeight: 600,
                        }}
                      >
                        Monthly Quota
                      </div>
                      <div
                        style={{
                          fontSize: "22px",
                          fontWeight: 800,
                          fontFamily: "monospace",
                          color: "#0f172a",
                          margin: "4px 0",
                        }}
                      >
                        {user?.quotaUsed?.toLocaleString() ?? "0"} /{" "}
                        {user?.quotaLimit?.toLocaleString() ?? "—"}
                      </div>
                      <div
                        style={{
                          height: "4px",
                          background: "#e2e8f0",
                          borderRadius: "2px",
                          marginTop: "10px",
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            width: `${Math.round(((user?.quotaUsed ?? 0) / (user?.quotaLimit || 1)) * 100)}%`,
                            height: "100%",
                            background: "#059669",
                          }}
                        />
                      </div>
                    </div>

                    <div
                      style={{
                        background: "#ffffff",
                        border: "1px solid #e2e8f0",
                        borderRadius: "8px",
                        padding: "18px",
                        boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.04em",
                          color: "#64748b",
                          fontWeight: 600,
                        }}
                      >
                        Configured Policies
                      </div>
                      <div
                        style={{
                          fontSize: "22px",
                          fontWeight: 800,
                          fontFamily: "monospace",
                          color: "#2563eb",
                          margin: "4px 0",
                        }}
                      >
                        {policies.length} Active
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#059669",
                          marginTop: "6px",
                          fontWeight: 600,
                        }}
                      >
                        Domain and method policies
                      </div>
                    </div>

                    <div
                      style={{
                        background: "#ffffff",
                        border: "1px solid #e2e8f0",
                        borderRadius: "8px",
                        padding: "18px",
                        boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.04em",
                          color: "#64748b",
                          fontWeight: 600,
                        }}
                      >
                        Database &amp; Vaults
                      </div>
                      <div
                        style={{
                          fontSize: "22px",
                          fontWeight: 800,
                          fontFamily: "monospace",
                          color: "#4f46e5",
                          margin: "4px 0",
                        }}
                      >
                        SQLite DO
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#64748b",
                          marginTop: "6px",
                        }}
                      >
                        Server-side AES-256-GCM envelope
                      </div>
                    </div>

                    <div
                      style={{
                        background: "#ffffff",
                        border: "1px solid #e2e8f0",
                        borderRadius: "8px",
                        padding: "18px",
                        boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                      }}
                    >
                      <div
                        style={{
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.04em",
                          color: "#64748b",
                          fontWeight: 600,
                        }}
                      >
                        Credential handling
                      </div>
                      <div
                        style={{
                          fontSize: "22px",
                          fontWeight: 800,
                          fontFamily: "monospace",
                          color: "#059669",
                          margin: "4px 0",
                        }}
                      >
                        Strict broker
                      </div>
                      <div
                        style={{
                          fontSize: "11px",
                          color: "#64748b",
                          marginTop: "6px",
                        }}
                      >
                        Volatile isolate RAM injection only
                      </div>
                    </div>
                  </div>

                  {/* Agent Bearer Key Panel */}
                  <div
                    style={{
                      background: "#ffffff",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      padding: "22px",
                      boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        marginBottom: "6px",
                      }}
                    >
                      <h3
                        style={{
                          fontSize: "14px",
                          fontWeight: 700,
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                          color: "#0f172a",
                        }}
                      >
                        <Key size={15} color="#059669" /> Companion
                        authentication
                      </h3>
                      <span
                        style={{
                          fontSize: "11px",
                          fontFamily: "monospace",
                          color: "#059669",
                          background: "#ecfdf5",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          fontWeight: 600,
                        }}
                      >
                        DEVICE-BOUND SESSION
                      </span>
                    </div>
                    <p
                      style={{
                        fontSize: "12px",
                        color: "#64748b",
                        marginBottom: "14px",
                        lineHeight: 1.4,
                      }}
                    >
                      Authorize the companion with explicit aliases. It stores a
                      DPoP key in the operating-system credential store and
                      signs each broker request.
                    </p>
                    <div style={{ display: "flex", gap: "8px" }}>
                      <input
                        type="text"
                        readOnly
                        value={
                          "agentsecret login --server " + window.location.origin
                        }
                        style={{
                          flex: 1,
                          background: "#f8fafc",
                          border: "1px solid #cbd5e1",
                          color: "#0f172a",
                          padding: "9px 12px",
                          borderRadius: "6px",
                          fontFamily: "monospace",
                          fontSize: "12px",
                        }}
                      />
                      <button
                        onClick={() =>
                          copyToClipboard(
                            "agentsecret login --server " +
                              window.location.origin,
                            "apiKey",
                          )
                        }
                        style={{
                          background: copiedKey ? "#059669" : "#0f172a",
                          color: "#ffffff",
                          border: "none",
                          padding: "9px 16px",
                          borderRadius: "6px",
                          fontSize: "12px",
                          fontWeight: 600,
                          cursor: "pointer",
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                        }}
                        className="btn-tactile"
                      >
                        {copiedKey ? (
                          <CheckCircle size={14} />
                        ) : (
                          <Copy size={14} />
                        )}{" "}
                        {copiedKey ? "Copied" : "Copy"}
                      </button>
                    </div>
                  </div>
                </>
              )}

              {/* TAB: SAVE SECRET */}
              {activeTab === "secrets" && (
                <section
                  aria-labelledby="save-secret-heading"
                  style={{
                    background: "#ffffff",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    padding: "24px",
                    boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                  }}
                >
                  <h2
                    id="save-secret-heading"
                    style={{ fontSize: "18px", margin: "0 0 6px" }}
                  >
                    Save secret
                  </h2>
                  <p style={{ color: "#64748b", fontSize: "13px" }}>
                    Create a concealed secure note or update one exact field in
                    the selected 1Password Connect vault. The secret value is
                    sent only with this authenticated request and is never
                    stored in browser storage or returned by the service.
                  </p>
                  <p style={{ color: "#64748b", fontSize: "12px" }}>
                    Writes are verified by reading the selected field back.
                    Updates do not have a conditional-write guarantee. Other
                    provider modes are not available here.
                  </p>

                  <form
                    aria-label="Find secret by reference"
                    onSubmit={handleFindSecret}
                    style={{
                      display: "grid",
                      gap: "14px",
                      maxWidth: "560px",
                      padding: "16px 0 20px",
                      borderBottom: "1px solid #e2e8f0",
                    }}
                  >
                    <h3 style={{ margin: 0, fontSize: "14px" }}>
                      Find by reference
                    </h3>
                    <label>
                      Read connection
                      <select
                        aria-label="Find connection"
                        required
                        value={findConnectionId}
                        onChange={(e) => {
                          findRequestVersion.current++;
                          setFindConnectionId(e.target.value);
                          setFindStatus("idle");
                          setFindResult(null);
                        }}
                        style={{
                          display: "block",
                          width: "100%",
                          marginTop: "6px",
                        }}
                      >
                        <option value="">Choose a connection</option>
                        {vaultConnections.map((connection) => (
                          <option
                            key={connection.id}
                            value={connection.id}
                            disabled={!connection.capabilities?.read}
                          >
                            {connection.alias} — {connection.provider} —{" "}
                            {connection.capabilities?.read
                              ? "read available"
                              : "read unavailable"}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Secret reference
                      <input
                        aria-label="Secret reference"
                        value={findReference}
                        maxLength={1024}
                        required
                        autoComplete="off"
                        onChange={(e) => {
                          findRequestVersion.current++;
                          setFindReference(e.target.value);
                          setFindStatus("idle");
                          setFindResult(null);
                        }}
                      />
                    </label>
                    <button
                      type="submit"
                      disabled={
                        findStatus === "searching" ||
                        !findConnectionId ||
                        !findReference.trim()
                      }
                      className="btn-tactile"
                      style={{
                        justifySelf: "start",
                        background: "#ffffff",
                        color: "#0f172a",
                        border: "1px solid #cbd5e1",
                        borderRadius: "6px",
                        padding: "9px 16px",
                        fontWeight: 600,
                      }}
                    >
                      {findStatus === "searching" ? "Checking…" : "Find secret"}
                    </button>
                  </form>
                  {findStatus === "found" && findResult && (
                    <p role="status">
                      Reference is available in {findResult.provider}:{" "}
                      {findResult.reference}. Secret values are never returned
                      here.
                    </p>
                  )}
                  {findStatus === "error" && (
                    <p role="alert">
                      Reference could not be verified for this connection.
                    </p>
                  )}

                  <section
                    aria-labelledby="private-input-requests-heading"
                    style={{
                      maxWidth: "560px",
                      marginTop: "20px",
                      padding: "16px",
                      border: "1px solid #cbd5e1",
                      borderRadius: "8px",
                      background: "#f8fafc",
                    }}
                  >
                    <h3
                      id="private-input-requests-heading"
                      style={{ margin: "0 0 8px", fontSize: "14px" }}
                    >
                      Agent save requests
                    </h3>
                    <p style={{ color: "#64748b", fontSize: "12px" }}>
                      Enter requested values here in your authenticated
                      dashboard. Values are sent directly to the selected
                      connection and are never returned to the requesting agent.
                    </p>
                    {privateInputRequests.length === 0 ? (
                      <p style={{ color: "#64748b", fontSize: "13px" }}>
                        No pending requests.
                      </p>
                    ) : (
                      <div style={{ display: "grid", gap: "14px" }}>
                        {privateInputRequests.map((request) => {
                          const connection = vaultConnections.find(
                            (item) => item.id === request.connectionId,
                          );
                          const requestExpired =
                            request.status === "pending" &&
                            request.expiresAt * 1000 <= Date.now();
                          return (
                            <article
                              key={request.requestId}
                              style={{
                                paddingTop: "12px",
                                borderTop: "1px solid #e2e8f0",
                              }}
                            >
                              <p
                                style={{ margin: "0 0 8px", fontSize: "13px" }}
                              >
                                <strong>{request.intent}</strong> for alias{" "}
                                <strong>{request.alias}</strong> in{" "}
                                {connection?.alias ?? "the selected connection"}
                                {request.intent !== "create" ? (
                                  <>
                                    {" "}
                                    at reference <code>{request.target}</code>
                                  </>
                                ) : (
                                  <>
                                    {" "}
                                    with title <strong>{request.target}</strong>
                                  </>
                                )}
                              </p>
                              {request.status === "pending" &&
                              !requestExpired &&
                              connection?.provider ===
                                "onepassword-service-account" ? (
                                <p
                                  style={{ color: "#475569", fontSize: "12px" }}
                                >
                                  This vault stays on your device. From the
                                  agent session that created the request,
                                  complete it in the enrolled companion with{" "}
                                  <code>
                                    agentsecret secrets fulfill --request-id{" "}
                                    {request.requestId}
                                  </code>
                                  . The service-account value is never sent to
                                  this page.
                                </p>
                              ) : request.status === "pending" &&
                                !requestExpired ? (
                                <form
                                  aria-label={`Fulfill save request for ${request.alias}`}
                                  onSubmit={(event) =>
                                    handleFulfillPrivateInput(event, request)
                                  }
                                  style={{ display: "grid", gap: "8px" }}
                                >
                                  <label>
                                    Secret value
                                    <input
                                      type="password"
                                      autoComplete="new-password"
                                      required
                                      maxLength={8192}
                                      value={
                                        privateInputDrafts[request.requestId] ??
                                        ""
                                      }
                                      disabled={
                                        privateInputSubmitting !== null ||
                                        request.expiresAt * 1000 <= Date.now()
                                      }
                                      onChange={(event) =>
                                        setPrivateInputDrafts((current) => ({
                                          ...current,
                                          [request.requestId]:
                                            event.target.value,
                                        }))
                                      }
                                    />
                                  </label>
                                  <button
                                    type="submit"
                                    disabled={
                                      !privateInputDrafts[request.requestId] ||
                                      privateInputSubmitting !== null ||
                                      request.expiresAt * 1000 <= Date.now()
                                    }
                                    className="btn-tactile"
                                    style={{
                                      justifySelf: "start",
                                      background: "#0f172a",
                                      color: "#ffffff",
                                      border: "none",
                                      borderRadius: "6px",
                                      padding: "8px 14px",
                                      fontWeight: 600,
                                    }}
                                  >
                                    {privateInputSubmitting ===
                                    request.requestId
                                      ? "Saving…"
                                      : request.intent === "ensure"
                                        ? "Ensure field"
                                        : "Save to vault"}
                                  </button>
                                </form>
                              ) : request.status === "saved" ? null : (
                                <p
                                  role={
                                    requestExpired ||
                                    request.status === "fulfilling"
                                      ? "status"
                                      : "alert"
                                  }
                                  style={{ color: "#9a3412" }}
                                >
                                  {requestExpired
                                    ? "This request expired before it was fulfilled. The agent must submit a new request."
                                    : request.status === "fulfilling"
                                      ? "This write is in progress. Check this panel again shortly for its result."
                                      : "The previous write outcome is unknown. Inspect the destination vault before asking the agent to start another save."}
                                </p>
                              )}
                              {privateInputFeedback[request.requestId] && (
                                <p
                                  role={
                                    /^(Saved and verified:|Updated and verified:|Already matched; no write was made:)/.test(
                                      privateInputFeedback[request.requestId],
                                    )
                                      ? "status"
                                      : "alert"
                                  }
                                >
                                  {privateInputFeedback[request.requestId]}
                                </p>
                              )}
                            </article>
                          );
                        })}
                      </div>
                    )}
                    {privateInputNextCursor && (
                      <button
                        type="button"
                        disabled={privateInputLoadingMore}
                        onClick={() => void handleLoadMorePrivateInputs()}
                        className="btn-tactile"
                        style={{ justifySelf: "start" }}
                      >
                        {privateInputLoadingMore
                          ? "Loading…"
                          : "Show older requests"}
                      </button>
                    )}
                  </section>

                  <form
                    aria-label="Save secret"
                    onSubmit={handleSaveSecret}
                    style={{
                      display: "grid",
                      gap: "16px",
                      maxWidth: "560px",
                      marginTop: "20px",
                    }}
                  >
                    <label>
                      Operation
                      <select
                        aria-label="Secret operation"
                        value={saveMode}
                        disabled={
                          saveStatus === "saving" ||
                          saveStatus === "unknown" ||
                          compareStatus === "checking" ||
                          ensureStatus === "checking" ||
                          ensureStatus === "unknown"
                        }
                        onChange={(e) => {
                          const mode = e.target.value as
                            "create" | "update" | "delete";
                          compareRequestVersion.current++;
                          setCompareStatus("idle");
                          setEnsureStatus("idle");
                          setSaveMode(mode);
                          setSaveOperationId("");
                          setSavedReference("");
                          setDeleteConfirmed(false);
                          if (mode === "delete") setSaveValue("");
                          setSaveStatus("idle");
                        }}
                        style={{
                          display: "block",
                          width: "100%",
                          marginTop: "6px",
                        }}
                      >
                        <option value="create">Create a new secret</option>
                        <option value="update">Update an exact field</option>
                        <option value="delete">Delete an exact field</option>
                      </select>
                    </label>
                    <label>
                      Destination connection
                      <select
                        aria-label="Destination connection"
                        required
                        value={saveConnectionId}
                        disabled={
                          saveStatus === "saving" ||
                          saveStatus === "unknown" ||
                          compareStatus === "checking" ||
                          ensureStatus === "checking" ||
                          ensureStatus === "unknown"
                        }
                        onChange={(e) => {
                          compareRequestVersion.current++;
                          setCompareStatus("idle");
                          setEnsureStatus("idle");
                          setSaveConnectionId(e.target.value);
                          setSaveOperationId("");
                          setSaveStatus("idle");
                          setSavedReference("");
                          setDeleteConfirmed(false);
                        }}
                        style={{
                          display: "block",
                          width: "100%",
                          marginTop: "6px",
                        }}
                      >
                        <option value="">Choose a connection</option>
                        {vaultConnections.map((connection) => {
                          const canCreate =
                            connection.provider === "onepassword-connect" &&
                            (saveMode === "delete"
                              ? connection.capabilities?.delete === true
                              : saveMode === "update"
                                ? connection.capabilities?.update === true
                                : connection.capabilities?.create === true);
                          return (
                            <option
                              key={connection.id}
                              value={connection.id}
                              disabled={!canCreate}
                            >
                              {connection.alias} — {connection.provider} —{" "}
                              {canCreate
                                ? `${saveMode} available`
                                : `${saveMode} unavailable`}
                            </option>
                          );
                        })}
                      </select>
                    </label>

                    {saveConnectionId && (
                      <p
                        style={{
                          margin: 0,
                          color: "#475569",
                          fontSize: "12px",
                        }}
                      >
                        Destination vault is the vault configured for this
                        connection. Create and update write one item/field;
                        delete removes only the exact field and preserves its
                        containing item and sibling fields.
                      </p>
                    )}

                    {saveMode === "update" || saveMode === "delete" ? (
                      <label>
                        {saveMode === "delete"
                          ? "Exact field reference to delete"
                          : "Exact field reference"}
                        <input
                          aria-label={
                            saveMode === "delete"
                              ? "Delete secret reference"
                              : "Update secret reference"
                          }
                          value={saveReference}
                          maxLength={1024}
                          required
                          autoComplete="off"
                          disabled={
                            saveStatus === "saving" ||
                            saveStatus === "unknown" ||
                            compareStatus === "checking" ||
                            ensureStatus === "checking" ||
                            ensureStatus === "unknown"
                          }
                          onChange={(e) => {
                            compareRequestVersion.current++;
                            setCompareStatus("idle");
                            setEnsureStatus("idle");
                            setSaveReference(e.target.value);
                            setSaveOperationId("");
                            setSavedReference("");
                            setSaveStatus("idle");
                            setDeleteConfirmed(false);
                          }}
                        />
                      </label>
                    ) : (
                      <label>
                        Item title
                        <input
                          aria-label="Secret title"
                          value={saveTitle}
                          maxLength={128}
                          required
                          autoComplete="off"
                          disabled={
                            saveStatus === "saving" || saveStatus === "unknown"
                          }
                          onChange={(e) => setSaveTitle(e.target.value)}
                        />
                      </label>
                    )}
                    {saveMode !== "delete" && (
                      <label>
                        Secret value
                        <input
                          aria-label="Secret value"
                          type="password"
                          value={saveValue}
                          maxLength={8192}
                          required
                          autoComplete="new-password"
                          disabled={
                            saveStatus === "saving" ||
                            saveStatus === "unknown" ||
                            compareStatus === "checking" ||
                            ensureStatus === "checking" ||
                            ensureStatus === "unknown"
                          }
                          onChange={(e) => {
                            compareRequestVersion.current++;
                            setCompareStatus("idle");
                            setEnsureStatus("idle");
                            setSaveValue(e.target.value);
                            setSavedReference("");
                            setSaveStatus("idle");
                          }}
                        />
                      </label>
                    )}

                    {saveMode === "update" && (
                      <div style={{ display: "grid", gap: "8px" }}>
                        <button
                          type="button"
                          disabled={
                            compareStatus === "checking" ||
                            ensureStatus === "checking" ||
                            saveStatus === "saving" ||
                            saveStatus === "unknown" ||
                            !saveConnectionId ||
                            !saveReference.trim() ||
                            !saveValue ||
                            !vaultConnections.find(
                              (connection) =>
                                connection.id === saveConnectionId &&
                                connection.capabilities?.read === true,
                            )
                          }
                          onClick={() => void handleCompareSecret()}
                          className="btn-tactile"
                          style={{
                            justifySelf: "start",
                            background: "#ffffff",
                            color: "#0f172a",
                            border: "1px solid #cbd5e1",
                            borderRadius: "6px",
                            padding: "8px 14px",
                            fontWeight: 600,
                          }}
                        >
                          {compareStatus === "checking"
                            ? "Comparing…"
                            : "Compare privately"}
                        </button>
                        <p
                          style={{
                            margin: 0,
                            color: "#64748b",
                            fontSize: "12px",
                          }}
                        >
                          Owner-only comparison against the exact field. Compare
                          privately never writes; Ensure field writes only when
                          values differ, then verifies the update. Agents cannot
                          call either operation.
                        </p>
                        {compareStatus === "match" && (
                          <p role="status">
                            The entered value matches the field. No write was
                            made.
                          </p>
                        )}
                        {compareStatus === "different" && (
                          <p role="status">
                            The entered value differs from the field. No write
                            was made.
                          </p>
                        )}
                        {compareStatus === "error" && (
                          <p role="alert">
                            The value could not be compared with this field.
                          </p>
                        )}
                        <button
                          type="button"
                          disabled={
                            ensureStatus === "checking" ||
                            compareStatus === "checking" ||
                            saveStatus === "saving" ||
                            !saveConnectionId ||
                            !saveReference.trim() ||
                            !saveValue ||
                            !vaultConnections.find(
                              (connection) =>
                                connection.id === saveConnectionId &&
                                connection.provider === "onepassword-connect" &&
                                connection.capabilities?.read === true &&
                                connection.capabilities?.update === true,
                            )
                          }
                          onClick={() => void handleEnsureSecret()}
                          className="btn-tactile"
                          style={{
                            justifySelf: "start",
                            background: "#ffffff",
                            color: "#0f172a",
                            border: "1px solid #cbd5e1",
                            borderRadius: "6px",
                            padding: "8px 14px",
                            fontWeight: 600,
                          }}
                        >
                          {ensureStatus === "checking"
                            ? "Ensuring…"
                            : ensureStatus === "unknown"
                              ? "Retry ensure safely"
                              : "Ensure field"}
                        </button>
                        {ensureStatus === "unchanged" && (
                          <p role="status">
                            The field already matches. No write was made.
                          </p>
                        )}
                        {ensureStatus === "updated" && (
                          <p role="status">
                            The field differed, so it was updated and verified.
                          </p>
                        )}
                        {ensureStatus === "unknown" && (
                          <p role="alert">
                            The update outcome is unknown. Retry the same ensure
                            operation to retrieve its receipt, or inspect the
                            selected vault before starting another operation.
                          </p>
                        )}
                        {ensureStatus === "error" && (
                          <p role="alert">
                            The field could not be ensured. Check the selected
                            connection and reference, then try again.
                          </p>
                        )}
                      </div>
                    )}

                    {saveMode === "delete" && (
                      <label style={{ display: "flex", gap: "8px" }}>
                        <input
                          aria-label="Confirm exact field deletion"
                          type="checkbox"
                          checked={deleteConfirmed}
                          disabled={
                            saveStatus === "saving" || saveStatus === "unknown"
                          }
                          onChange={(e) => setDeleteConfirmed(e.target.checked)}
                        />
                        I understand that this permanently removes the
                        referenced field.
                      </label>
                    )}

                    <button
                      type="submit"
                      disabled={
                        saveStatus === "saving" ||
                        compareStatus === "checking" ||
                        ensureStatus === "checking" ||
                        !saveConnectionId ||
                        (saveMode === "update" || saveMode === "delete"
                          ? !saveReference.trim()
                          : !saveTitle.trim()) ||
                        (saveMode !== "delete" && !saveValue) ||
                        (saveMode === "delete" && !deleteConfirmed)
                      }
                      className="btn-tactile"
                      style={{
                        justifySelf: "start",
                        background: "#0f172a",
                        color: "#ffffff",
                        border: "none",
                        borderRadius: "6px",
                        padding: "10px 18px",
                        fontWeight: 600,
                        cursor: saveStatus === "saving" ? "wait" : "pointer",
                      }}
                    >
                      {saveStatus === "saving"
                        ? "Saving…"
                        : saveStatus === "unknown"
                          ? "Retry safely"
                          : saveMode === "delete"
                            ? "Delete field"
                            : saveMode === "update"
                              ? "Update field"
                              : "Create secret"}
                    </button>
                  </form>

                  {vaultConnections.filter(
                    (connection) =>
                      connection.provider === "onepassword-connect" &&
                      (saveMode === "delete"
                        ? connection.capabilities?.delete === true
                        : saveMode === "update"
                          ? connection.capabilities?.update === true
                          : connection.capabilities?.create === true),
                  ).length === 0 && (
                    <p role="status" style={{ color: "#64748b" }}>
                      No {saveMode}-capable connection is connected. Add a
                      1Password Connect connection with this capability in Vault
                      Connections first.
                    </p>
                  )}
                  {saveStatus === "saved" && (
                    <div role="status" style={{ marginTop: "18px" }}>
                      <strong>
                        {saveMode === "delete"
                          ? "Secret field deleted"
                          : `Secret ${saveMode === "update" ? "updated" : "created"}`}{" "}
                        and verified.
                      </strong>
                      <div>
                        {saveMode === "delete" ? "Deleted" : "Saved"} reference:
                      </div>
                      <code>{savedReference}</code>
                    </div>
                  )}
                  {saveStatus === "error" && (
                    <p role="alert">
                      The operation failed. Check the selected connection and
                      target, then try again.
                    </p>
                  )}
                  {saveStatus === "unknown" && (
                    <p role="alert">
                      The operation outcome is not confirmed. Retry safely to
                      check the same operation, or inspect the selected vault
                      before starting a different operation.
                    </p>
                  )}
                </section>
              )}

              {/* TAB: VAULT CONNECTIONS */}
              {activeTab === "vaults" && (
                <div
                  style={{
                    background: "#ffffff",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    padding: "24px",
                    boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                  }}
                >
                  <div style={{ marginBottom: "18px" }}>
                    <h3
                      style={{
                        fontSize: "16px",
                        fontWeight: 800,
                        color: "#0f172a",
                      }}
                    >
                      Password Manager &amp; Vault Connectors
                    </h3>
                    <p
                      style={{
                        fontSize: "12px",
                        color: "#64748b",
                        marginTop: "3px",
                      }}
                    >
                      Cloud tokens entered here travel over HTTPS to the trusted
                      broker, which encrypts them with a separate AES-GCM key
                      before storing them in the tenant authority.
                      Service-account tokens and password-manager profiles stay
                      in the local Keychain; this page receives only safe
                      identifiers.
                    </p>
                  </div>

                  <section
                    aria-label="Provider availability"
                    style={{
                      margin: "0 0 22px",
                      padding: "14px 16px",
                      background: "#f8fafc",
                      border: "1px solid #e2e8f0",
                      borderRadius: "7px",
                    }}
                  >
                    <h4 style={{ margin: "0 0 10px", fontSize: "13px" }}>
                      Provider availability
                    </h4>
                    <ul
                      style={{
                        margin: 0,
                        paddingLeft: "18px",
                        display: "grid",
                        gap: "6px",
                        fontSize: "12px",
                        color: "#475569",
                      }}
                    >
                      {(
                        Object.keys(
                          PROVIDER_MODE_LABELS,
                        ) as ReleaseProviderMode[]
                      ).map((mode) => {
                        const capability = providerModes[mode];
                        const availability = !capability
                          ? "Capability status unavailable"
                          : capability.status === "requires-companion"
                            ? "Companion required"
                            : capability.status === "unsupported"
                              ? "Unavailable"
                              : `${capability.read ? "Read available" : "Read unavailable"} · ${capability.create || capability.update ? "save available" : "save unavailable"}`;
                        return (
                          <li key={mode}>
                            <strong>{PROVIDER_MODE_LABELS[mode]}:</strong>{" "}
                            <span aria-label={availability}>
                              {availability}
                            </span>
                            {capability?.reason ? (
                              <span> {capability.reason}</span>
                            ) : null}
                          </li>
                        );
                      })}
                    </ul>
                  </section>

                  <form
                    onSubmit={handleSaveVault}
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "16px",
                    }}
                  >
                    <label>
                      Connection name
                      <input
                        value={connectionAlias}
                        onChange={(e) => setConnectionAlias(e.target.value)}
                        maxLength={64}
                        required
                        autoComplete="off"
                        placeholder="work"
                      />
                    </label>
                    <div>
                      <label
                        style={{
                          display: "block",
                          fontSize: "11px",
                          textTransform: "uppercase",
                          letterSpacing: "0.04em",
                          color: "#64748b",
                          marginBottom: "6px",
                          fontWeight: 600,
                        }}
                      >
                        Select Password Manager / Secrets Engine
                      </label>
                      <select
                        value={vaultProvider}
                        onChange={(e) =>
                          setVaultProvider(e.target.value as any)
                        }
                        style={{
                          width: "100%",
                          background: "#ffffff",
                          border: "1px solid #cbd5e1",
                          color: "#0f172a",
                          padding: "10px 12px",
                          borderRadius: "6px",
                          fontSize: "13px",
                        }}
                      >
                        <option value="bitwarden_secrets">
                          Bitwarden Secrets Manager (BWS - Machine Token)
                        </option>
                        <option value="bitwarden_password">
                          Bitwarden Password Manager (local companion)
                        </option>
                        <option value="onepassword_service_account">
                          1Password service account (local companion)
                        </option>
                        <option value="lastpass">
                          LastPass (local companion)
                        </option>
                        {replaceConnectionId &&
                          vaultProvider === "onepassword" && (
                            <option value="onepassword">
                              1Password Connect (existing connection)
                            </option>
                          )}
                      </select>
                    </div>

                    {/* Bitwarden Secrets Manager */}
                    {vaultProvider === "bitwarden_secrets" && (
                      <div
                        style={{
                          background: "#f8fafc",
                          padding: "16px",
                          borderRadius: "6px",
                          border: "1px solid #e2e8f0",
                        }}
                      >
                        <div
                          style={{
                            fontSize: "12px",
                            fontWeight: 700,
                            color: "#0f172a",
                            marginBottom: "6px",
                          }}
                        >
                          Bitwarden Secrets Manager Configuration
                        </div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            color: "#64748b",
                            marginBottom: "4px",
                            fontWeight: 600,
                          }}
                        >
                          BWS Access Token (format:
                          0.&lt;clientId&gt;.&lt;clientSecret&gt;:&lt;seedBase64&gt;)
                        </label>
                        <input
                          type="password"
                          value={bwsToken}
                          onChange={(e) => setBwsToken(e.target.value)}
                          placeholder="0.2a8f...:base64seed=="
                          style={{
                            width: "100%",
                            background: "#ffffff",
                            border: "1px solid #cbd5e1",
                            color: "#0f172a",
                            padding: "9px 12px",
                            borderRadius: "6px",
                            fontFamily: "monospace",
                            fontSize: "12px",
                          }}
                        />
                      </div>
                    )}

                    {vaultSaveStatus === "error" && (
                      <p role="alert">
                        Vault connection was not saved. Verify the configuration
                        and server keyring.
                      </p>
                    )}
                    {["bitwarden_password", "lastpass"].includes(
                      vaultProvider,
                    ) && (
                      <div
                        style={{
                          background: "#f8fafc",
                          padding: "16px",
                          borderRadius: "6px",
                          border: "1px solid #e2e8f0",
                        }}
                      >
                        <div
                          style={{
                            fontSize: "12px",
                            fontWeight: 700,
                            color: "#0f172a",
                            marginBottom: "6px",
                          }}
                        >
                          Local companion profile
                        </div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            color: "#64748b",
                            marginBottom: "4px",
                            fontWeight: 600,
                          }}
                        >
                          Profile ID
                        </label>
                        <input
                          type="text"
                          value={companionProfileId}
                          onChange={(e) =>
                            setCompanionProfileId(e.target.value)
                          }
                          placeholder="bitwarden-work or lastpass-test"
                          style={{
                            width: "100%",
                            background: "#ffffff",
                            border: "1px solid #cbd5e1",
                            color: "#0f172a",
                            padding: "9px 12px",
                            borderRadius: "6px",
                            fontFamily: "monospace",
                            fontSize: "12px",
                          }}
                        />
                      </div>
                    )}

                    {vaultProvider === "onepassword_service_account" && (
                      <label>
                        1Password vault ID
                        <input
                          value={serviceAccountVaultId}
                          onChange={(e) =>
                            setServiceAccountVaultId(e.target.value)
                          }
                          required
                          autoComplete="off"
                        />
                      </label>
                    )}
                    {vaultProvider === "onepassword" && replaceConnectionId && (
                      <>
                        <label>
                          1Password Connect access token
                          <input
                            type="password"
                            value={opToken}
                            onChange={(e) => setOpToken(e.target.value)}
                            required
                          />
                        </label>
                        <label>
                          Connect server HTTPS URL
                          <input
                            type="url"
                            value={connectUrl}
                            onChange={(e) => setConnectUrl(e.target.value)}
                            required
                          />
                        </label>
                        <label>
                          Vault ID
                          <input
                            value={connectVault}
                            onChange={(e) => setConnectVault(e.target.value)}
                            required
                          />
                        </label>
                      </>
                    )}
                    <button
                      type="submit"
                      style={{
                        alignSelf: "flex-start",
                        background: "#0f172a",
                        color: "#ffffff",
                        border: "none",
                        padding: "10px 20px",
                        borderRadius: "6px",
                        fontSize: "13px",
                        fontWeight: 600,
                        cursor: "pointer",
                      }}
                      className="btn-tactile"
                    >
                      {replaceConnectionId
                        ? "Replace Connection Credentials"
                        : "Encrypt & Create Vault Connection"}
                    </button>
                  </form>

                  {vaultSaveStatus === "success" && (
                    <div
                      style={{
                        marginTop: "16px",
                        padding: "12px 14px",
                        background: "#ecfdf5",
                        border: "1px solid #a7f3d0",
                        color: "#065f46",
                        borderRadius: "6px",
                        fontSize: "12px",
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                      }}
                    >
                      <CheckCircle size={15} /> Vault connection encrypted with
                      the separate server keyring and saved.
                    </div>
                  )}
                  <section
                    aria-label="Connected vaults"
                    style={{ marginTop: "20px" }}
                  >
                    <h4>Connected vaults</h4>
                    {vaultConnections.length === 0 ? (
                      <p>No vault connections yet.</p>
                    ) : (
                      <ul>
                        {vaultConnections.map((connection) => (
                          <li key={connection.id}>
                            {connection.alias} · {connection.provider} ·
                            revision {connection.revision} ·{" "}
                            {connection.capabilities
                              ? `${connection.capabilities.read ? "read" : "no read"}; ${connection.capabilities.create || connection.capabilities.update ? "write available" : "save unavailable"}`
                              : "capabilities unavailable"}{" "}
                            <button
                              type="button"
                              onClick={() => {
                                clearVaultCredentialDraft();
                                setReplaceConnectionId(connection.id);
                                setConnectionAlias(connection.alias);
                                setVaultProvider(
                                  connection.provider === "onepassword-connect"
                                    ? "onepassword"
                                    : connection.provider ===
                                        "bitwarden-password-manager"
                                      ? "bitwarden_password"
                                      : connection.provider ===
                                          "onepassword-service-account"
                                        ? "onepassword_service_account"
                                        : connection.provider === "lastpass"
                                          ? "lastpass"
                                          : "bitwarden_secrets",
                                );
                              }}
                            >
                              Replace credentials
                            </button>
                            <button
                              type="button"
                              onClick={async () => {
                                const res = await fetch(
                                  `/api/user/vault-connections?id=${encodeURIComponent(connection.id)}`,
                                  { method: "DELETE" },
                                );
                                if (res.ok) {
                                  await refreshVaultConnections();
                                  await refreshPolicies();
                                } else
                                  setDashboardNotice(
                                    "Connection could not be disconnected. Rebind affected policies to continue.",
                                  );
                              }}
                            >
                              Disconnect
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                    <p role="status">
                      Replacing or disconnecting a connection disables policies
                      bound to its prior revision until they are saved again.
                    </p>
                  </section>
                </div>
              )}

              {/* TAB: SECRET POLICIES */}
              {activeTab === "policies" && (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "16px",
                  }}
                >
                  <div
                    style={{
                      background: "#ffffff",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      padding: "22px",
                      boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                    }}
                  >
                    <h3
                      style={{
                        fontSize: "15px",
                        fontWeight: 800,
                        marginBottom: "12px",
                        color: "#0f172a",
                      }}
                    >
                      Register New Secret Alias Policy
                    </h3>
                    <form
                      onSubmit={handleAddPolicy}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr",
                        gap: "12px",
                      }}
                    >
                      <label>
                        Vault connection
                        <select
                          value={selectedConnectionId}
                          onChange={(e) => {
                            const connectionId = e.target.value;
                            setSelectedConnectionId(connectionId);
                            const selectedConnection = vaultConnections.find(
                              (connection) => connection.id === connectionId,
                            );
                            if (
                              selectedConnection?.provider !==
                              "onepassword-connect"
                            )
                              setNewFindLoginEnabled(false);
                          }}
                          required
                        >
                          <option value="">Select a connected vault</option>
                          {vaultConnections.map((connection) => (
                            <option key={connection.id} value={connection.id}>
                              {connection.alias} ({connection.provider})
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        Provider secret reference (Bitwarden UUID or
                        item#/fields/field)
                        <input
                          value={newSecretId}
                          onChange={(e) => setNewSecretId(e.target.value)}
                          placeholder="Provider reference"
                        />
                      </label>
                      <div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            color: "#64748b",
                            marginBottom: "4px",
                            fontWeight: 600,
                          }}
                        >
                          Secret Alias (e.g. AWS_DYNAMO)
                        </label>
                        <input
                          type="text"
                          value={newAlias}
                          onChange={(e) => setNewAlias(e.target.value)}
                          placeholder="MY_SERVICE_KEY"
                          style={{
                            width: "100%",
                            background: "#ffffff",
                            border: "1px solid #cbd5e1",
                            color: "#0f172a",
                            padding: "8px 10px",
                            borderRadius: "6px",
                            fontFamily: "monospace",
                            fontSize: "12px",
                          }}
                        />
                      </div>
                      <div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            color: "#64748b",
                            marginBottom: "4px",
                            fontWeight: 600,
                          }}
                        >
                          Allowed Domains (comma-separated)
                        </label>
                        <input
                          type="text"
                          value={newDomains}
                          onChange={(e) => setNewDomains(e.target.value)}
                          placeholder="api.service.com, *.service.com"
                          style={{
                            width: "100%",
                            background: "#ffffff",
                            border: "1px solid #cbd5e1",
                            color: "#0f172a",
                            padding: "8px 10px",
                            borderRadius: "6px",
                            fontFamily: "monospace",
                            fontSize: "12px",
                          }}
                        />
                      </div>
                      <div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            color: "#64748b",
                            marginBottom: "4px",
                            fontWeight: 600,
                          }}
                        >
                          Allowed HTTP Methods
                        </label>
                        <input
                          type="text"
                          value={newMethods}
                          onChange={(e) => setNewMethods(e.target.value)}
                          placeholder="GET, POST"
                          style={{
                            width: "100%",
                            background: "#ffffff",
                            border: "1px solid #cbd5e1",
                            color: "#0f172a",
                            padding: "8px 10px",
                            borderRadius: "6px",
                            fontSize: "12px",
                          }}
                        />
                      </div>
                      <div>
                        <label
                          style={{
                            display: "block",
                            fontSize: "11px",
                            color: "#64748b",
                            marginBottom: "4px",
                            fontWeight: 600,
                          }}
                        >
                          Description
                        </label>
                        <input
                          type="text"
                          value={newDesc}
                          onChange={(e) => setNewDesc(e.target.value)}
                          placeholder="Brief description for LLM catalog"
                          style={{
                            width: "100%",
                            background: "#ffffff",
                            border: "1px solid #cbd5e1",
                            color: "#0f172a",
                            padding: "8px 10px",
                            borderRadius: "6px",
                            fontSize: "12px",
                          }}
                        />
                      </div>
                      <label style={{ gridColumn: "1 / -1" }}>
                        Credential placement
                        <select
                          aria-label="Credential placement"
                          value={newInjectionType}
                          onChange={(event) =>
                            setNewInjectionType(
                              event.target.value as
                                "bearer" | "body_placeholder",
                            )
                          }
                        >
                          <option value="bearer">
                            Authorization: Bearer header
                          </option>
                          <option value="body_placeholder">
                            One explicit request-body placeholder
                          </option>
                        </select>
                        {newInjectionType === "body_placeholder" && (
                          <p style={{ margin: "6px 0 0", color: "#64748b" }}>
                            Put exactly one{" "}
                            <code>{"{{AGENTSECRET_SECRET}}"}</code> marker in
                            each request body. Use `text/plain`, or put the
                            marker in a JSON string value or JSON value slot
                            (never a key or substring). The broker substitutes
                            after authorizing the request.
                          </p>
                        )}
                      </label>
                      <div style={{ gridColumn: "1 / -1", marginTop: "4px" }}>
                        {vaultConnections.some(
                          (connection) =>
                            connection.id === selectedConnectionId &&
                            connection.provider === "onepassword-connect",
                        ) && (
                          <fieldset
                            style={{
                              border: "1px solid #cbd5e1",
                              borderRadius: "6px",
                              padding: "10px 12px",
                              marginBottom: "10px",
                            }}
                          >
                            <legend
                              style={{ fontSize: "12px", fontWeight: 700 }}
                            >
                              Owner-pinned Connect login lookup
                            </legend>
                            <label>
                              <input
                                type="checkbox"
                                checked={newFindLoginEnabled}
                                onChange={(event) =>
                                  setNewFindLoginEnabled(event.target.checked)
                                }
                              />{" "}
                              Allow lookup by this exact login locator
                            </label>
                            {newFindLoginEnabled && (
                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "1fr 1fr",
                                  gap: "10px",
                                  marginTop: "10px",
                                }}
                              >
                                <label>
                                  Exact Connect item title
                                  <input
                                    value={newFindLoginTitle}
                                    onChange={(event) =>
                                      setNewFindLoginTitle(event.target.value)
                                    }
                                    maxLength={128}
                                    required
                                  />
                                </label>
                                <label>
                                  Exact username
                                  <input
                                    value={newFindLoginUsername}
                                    onChange={(event) =>
                                      setNewFindLoginUsername(
                                        event.target.value,
                                      )
                                    }
                                    maxLength={512}
                                    required
                                  />
                                </label>
                                <label style={{ gridColumn: "1 / -1" }}>
                                  Exact item URLs (one per line)
                                  <textarea
                                    value={newFindLoginUris}
                                    onChange={(event) =>
                                      setNewFindLoginUris(event.target.value)
                                    }
                                    rows={3}
                                    required
                                  />
                                </label>
                                <label>
                                  Exact password field label (optional)
                                  <input
                                    value={newFindLoginFieldPath}
                                    onChange={(event) =>
                                      setNewFindLoginFieldPath(
                                        event.target.value,
                                      )
                                    }
                                    maxLength={256}
                                  />
                                </label>
                                <p style={{ gridColumn: "1 / -1", margin: 0 }}>
                                  Lookup searches only this exact title. The
                                  login's username, URL set, password field ID
                                  from the provider reference, and optional
                                  label are checked before a result is returned.
                                </p>
                              </div>
                            )}
                          </fieldset>
                        )}
                        {vaultConnections.some(
                          (connection) =>
                            connection.id === selectedConnectionId &&
                            connection.provider === "onepassword-connect",
                        ) ? (
                          <fieldset
                            style={{
                              border: "1px solid #cbd5e1",
                              borderRadius: "6px",
                              padding: "10px 12px",
                              marginBottom: "10px",
                            }}
                          >
                            <legend
                              style={{ fontSize: "12px", fontWeight: 700 }}
                            >
                              Agent vault write grant
                            </legend>
                            <label style={{ marginRight: "18px" }}>
                              <input
                                type="checkbox"
                                checked={newSecretWriteCreate}
                                onChange={(event) =>
                                  setNewSecretWriteCreate(event.target.checked)
                                }
                              />{" "}
                              Allow creating a secret in this connection
                            </label>
                            <label>
                              <input
                                type="checkbox"
                                checked={newSecretWriteUpdate}
                                onChange={(event) =>
                                  setNewSecretWriteUpdate(event.target.checked)
                                }
                              />{" "}
                              Allow updating this policy’s exact reference
                            </label>
                            <label
                              style={{ display: "block", marginTop: "6px" }}
                            >
                              <input
                                type="checkbox"
                                checked={newSecretWriteDelete}
                                onChange={(event) =>
                                  setNewSecretWriteDelete(event.target.checked)
                                }
                              />{" "}
                              Allow deleting this policy’s exact reference
                            </label>
                            <p
                              style={{
                                fontSize: "11px",
                                color: "#64748b",
                                margin: "6px 0 0",
                              }}
                            >
                              Write access is separately requested at CLI login
                              and bound to this alias. No selection means
                              read-only.
                            </p>
                          </fieldset>
                        ) : (
                          <p
                            style={{
                              fontSize: "11px",
                              color: "#64748b",
                              margin: "0 0 10px",
                            }}
                          >
                            Agent vault writes are currently supported for
                            1Password Connect connections only.
                          </p>
                        )}
                        <button
                          type="submit"
                          style={{
                            background: "#0f172a",
                            color: "#ffffff",
                            border: "none",
                            padding: "8px 16px",
                            borderRadius: "6px",
                            fontSize: "12px",
                            fontWeight: 600,
                            cursor: "pointer",
                          }}
                          className="btn-tactile"
                        >
                          + Register Policy
                        </button>
                      </div>
                    </form>
                  </div>

                  <div
                    style={{
                      background: "#ffffff",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      padding: "22px",
                      boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                    }}
                  >
                    <h3
                      style={{
                        fontSize: "15px",
                        fontWeight: 800,
                        marginBottom: "14px",
                        color: "#0f172a",
                      }}
                    >
                      Active Whitelisted Policies
                    </h3>
                    <table
                      style={{
                        width: "100%",
                        borderCollapse: "collapse",
                        fontSize: "12px",
                      }}
                    >
                      <thead>
                        <tr
                          style={{
                            borderBottom: "1px solid #e2e8f0",
                            color: "#64748b",
                            textAlign: "left",
                          }}
                        >
                          <th style={{ padding: "8px" }}>Alias</th>
                          <th style={{ padding: "8px" }}>Target Domains</th>
                          <th style={{ padding: "8px" }}>Methods</th>
                          <th style={{ padding: "8px" }}>
                            Credential placement
                          </th>
                          <th style={{ padding: "8px" }}>Description</th>
                          <th style={{ padding: "8px" }}>Firewall</th>
                          <th style={{ padding: "8px" }}>Locator</th>
                        </tr>
                      </thead>
                      <tbody>
                        {policies.map((p) => (
                          <React.Fragment key={p.alias}>
                            <tr style={{ borderBottom: "1px solid #f1f5f9" }}>
                              <td
                                style={{
                                  padding: "10px 8px",
                                  fontFamily: "monospace",
                                  color: "#2563eb",
                                  fontWeight: 600,
                                }}
                              >
                                {p.alias}
                              </td>
                              <td style={{ padding: "10px 8px" }}>
                                <code>{p.domains}</code>
                              </td>
                              <td
                                style={{
                                  padding: "10px 8px",
                                  color: "#64748b",
                                }}
                              >
                                {p.methods}
                              </td>
                              <td style={{ padding: "10px 8px" }}>
                                {p.injectionType === "body_placeholder" ? (
                                  <>
                                    Request body: one{" "}
                                    <code>{"{{AGENTSECRET_SECRET}}"}</code>
                                  </>
                                ) : (
                                  p.injectionType || "bearer"
                                )}
                              </td>
                              <td
                                style={{
                                  padding: "10px 8px",
                                  color: "#334155",
                                }}
                              >
                                {p.desc}
                              </td>
                              <td
                                style={{
                                  padding: "10px 8px",
                                  color: "#059669",
                                  fontWeight: 600,
                                }}
                              >
                                ✓ Whitelisted
                              </td>
                              <td style={{ padding: "10px 8px" }}>
                                {vaultConnections.some(
                                  (connection) =>
                                    connection.id === p.connectionId &&
                                    connection.provider ===
                                      "onepassword-connect",
                                ) && p.secretId ? (
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setEditingLoginAlias(p.alias);
                                      const selector = p.findSelector;
                                      const enabled =
                                        selector?.kind === "login_lookup";
                                      setEditLoginEnabled(enabled);
                                      setEditLoginTitle(
                                        enabled ? selector.title : "",
                                      );
                                      setEditLoginUsername(
                                        enabled ? selector.username || "" : "",
                                      );
                                      setEditLoginUris(
                                        enabled
                                          ? (selector.uris || []).join("\n")
                                          : "",
                                      );
                                      setEditLoginFieldPath(
                                        enabled ? selector.fieldPath || "" : "",
                                      );
                                    }}
                                  >
                                    {p.findSelector?.kind === "login_lookup"
                                      ? "Edit login lookup"
                                      : "Configure login lookup"}
                                  </button>
                                ) : (
                                  "—"
                                )}
                              </td>
                            </tr>
                            {editingLoginAlias === p.alias && (
                              <tr>
                                <td colSpan={7} style={{ padding: "12px" }}>
                                  <form
                                    aria-label={`Edit login lookup ${p.alias}`}
                                    onSubmit={handleUpdateLoginLocator}
                                    style={{ display: "grid", gap: "8px" }}
                                  >
                                    <label>
                                      <input
                                        type="checkbox"
                                        checked={editLoginEnabled}
                                        onChange={(event) =>
                                          setEditLoginEnabled(
                                            event.target.checked,
                                          )
                                        }
                                      />{" "}
                                      Enable this exact login lookup
                                    </label>
                                    {editLoginEnabled && (
                                      <>
                                        <label>
                                          Exact Connect item title
                                          <input
                                            value={editLoginTitle}
                                            onChange={(event) =>
                                              setEditLoginTitle(
                                                event.target.value,
                                              )
                                            }
                                            maxLength={128}
                                            required
                                          />
                                        </label>
                                        <label>
                                          Exact username
                                          <input
                                            value={editLoginUsername}
                                            onChange={(event) =>
                                              setEditLoginUsername(
                                                event.target.value,
                                              )
                                            }
                                            maxLength={512}
                                            required
                                          />
                                        </label>
                                        <label>
                                          Exact item URLs (one per line)
                                          <textarea
                                            value={editLoginUris}
                                            onChange={(event) =>
                                              setEditLoginUris(
                                                event.target.value,
                                              )
                                            }
                                            rows={3}
                                            required
                                          />
                                        </label>
                                        <label>
                                          Exact password field label (optional)
                                          <input
                                            value={editLoginFieldPath}
                                            onChange={(event) =>
                                              setEditLoginFieldPath(
                                                event.target.value,
                                              )
                                            }
                                            maxLength={256}
                                          />
                                        </label>
                                      </>
                                    )}
                                    <p>
                                      Updating this policy invalidates existing
                                      agent grants. Those agents must consent
                                      again.
                                    </p>
                                    <div>
                                      <button type="submit">
                                        Save locator
                                      </button>{" "}
                                      <button
                                        type="button"
                                        onClick={() =>
                                          setEditingLoginAlias(null)
                                        }
                                      >
                                        Cancel
                                      </button>
                                    </div>
                                  </form>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <div
                    style={{
                      background: "#ffffff",
                      border: "1px solid #e2e8f0",
                      borderRadius: "8px",
                      padding: "22px",
                      boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                    }}
                  >
                    <h3
                      style={{
                        fontSize: "15px",
                        fontWeight: 800,
                        marginBottom: "8px",
                        color: "#0f172a",
                      }}
                    >
                      Protected Local Executors and Grants
                    </h3>
                    <p style={{ color: "#64748b", fontSize: "12px" }}>
                      Run <code>agentsecret browser identity</code> on the
                      trusted Mac, then paste its public JSON below. Private
                      keys never leave the dedicated Keychain item. Grants are
                      short-lived and single-use. Browser execution remains
                      disabled until the managed runtime is qualified.
                    </p>
                    <form
                      onSubmit={handleApproveExecutor}
                      style={{ display: "grid", gap: "10px" }}
                    >
                      <label>
                        Public executor identity JSON
                        <textarea
                          aria-label="Public executor identity JSON"
                          rows={5}
                          value={executorApproval}
                          onChange={(event) =>
                            setExecutorApproval(event.target.value)
                          }
                          placeholder='{"status":"executor_identity","identity":{"executorId":"exe_…","publicJwk":{…}}}'
                          spellCheck={false}
                          required
                        />
                      </label>
                      <button
                        type="submit"
                        className="btn-tactile"
                        style={{ justifySelf: "start" }}
                      >
                        Approve public identity
                      </button>
                    </form>
                    {executorFeedback && (
                      <p role="status" style={{ color: "#475569" }}>
                        {executorFeedback}
                      </p>
                    )}
                    {browserExecutors.length > 0 && (
                      <div style={{ margin: "16px 0" }}>
                        <strong>Enrolled executors</strong>
                        <ul>
                          {browserExecutors.map((executor) => (
                            <li key={executor.executorId}>
                              <code>{executor.executorId}</code> · enrolled{" "}
                              {new Date(
                                executor.enrolledAt * 1000,
                              ).toLocaleString()}{" "}
                              <button
                                type="button"
                                onClick={() =>
                                  void handleRevokeExecutor(executor.executorId)
                                }
                              >
                                Revoke
                              </button>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    <form
                      onSubmit={handleIssueBrowserGrant}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr 1fr",
                        gap: "12px",
                      }}
                    >
                      <label>
                        Executor
                        <select
                          aria-label="Protected action executor"
                          value={grantExecutorId}
                          onChange={(event) =>
                            setGrantExecutorId(event.target.value)
                          }
                          required
                        >
                          <option value="">Select an executor</option>
                          {browserExecutors.map((executor) => (
                            <option
                              key={executor.executorId}
                              value={executor.executorId}
                            >
                              {executor.executorId}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        Secret alias
                        <select
                          aria-label="Protected action alias"
                          value={grantAlias}
                          onChange={(event) =>
                            setGrantAlias(event.target.value)
                          }
                          required
                        >
                          <option value="">Select an alias</option>
                          {policies.map((policy) => (
                            <option key={policy.alias} value={policy.alias}>
                              {policy.alias}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        Exact HTTPS origin
                        <input
                          aria-label="Protected action origin"
                          value={grantOrigin}
                          onChange={(event) =>
                            setGrantOrigin(event.target.value)
                          }
                          placeholder="https://app.example.com"
                          required
                        />
                      </label>
                      <label>
                        Actions (comma separated)
                        <input
                          aria-label="Protected action kinds"
                          value={grantActions}
                          onChange={(event) =>
                            setGrantActions(event.target.value)
                          }
                          placeholder="fill,totp"
                          required
                        />
                      </label>
                      <label style={{ gridColumn: "1 / -1" }}>
                        Exact field selector
                        <input
                          aria-label="Protected action field selector"
                          value={grantSelector}
                          onChange={(event) =>
                            setGrantSelector(event.target.value)
                          }
                          placeholder="#password"
                          required
                        />
                      </label>
                      <button
                        type="submit"
                        className="btn-tactile"
                        style={{ justifySelf: "start" }}
                      >
                        Issue 60-second grant
                      </button>
                    </form>
                    {grantFeedback && (
                      <p role="status" style={{ color: "#475569" }}>
                        {grantFeedback}
                      </p>
                    )}
                    {browserGrants.length > 0 && (
                      <div style={{ marginTop: "16px", overflowX: "auto" }}>
                        <table style={{ width: "100%" }}>
                          <thead>
                            <tr>
                              <th>Alias</th>
                              <th>Origin</th>
                              <th>Actions</th>
                              <th>Expiry</th>
                              <th>State</th>
                              <th />
                            </tr>
                          </thead>
                          <tbody>
                            {browserGrants.map((grant) => (
                              <tr key={grant.grantId}>
                                <td>{grant.alias}</td>
                                <td>{grant.origin}</td>
                                <td>{grant.kinds.join(", ")}</td>
                                <td>
                                  {new Date(
                                    grant.expiresAt * 1000,
                                  ).toLocaleTimeString()}
                                </td>
                                <td>
                                  {grant.revokedAt
                                    ? "revoked"
                                    : grant.redeemedAt
                                      ? "redeemed"
                                      : "unredeemed"}
                                </td>
                                <td>
                                  {!grant.revokedAt && !grant.redeemedAt && (
                                    <button
                                      type="button"
                                      onClick={() =>
                                        void handleRevokeBrowserGrant(
                                          grant.grantId,
                                        )
                                      }
                                    >
                                      Revoke
                                    </button>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB: EGRESS SIMULATOR */}
              {activeTab === "simulator" && (
                <div
                  style={{
                    background: "#ffffff",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    padding: "24px",
                    boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
                  }}
                >
                  <h3
                    style={{
                      fontSize: "16px",
                      fontWeight: 800,
                      marginBottom: "6px",
                      color: "#0f172a",
                    }}
                  >
                    In-Dashboard Egress Simulator
                  </h3>
                  <p
                    style={{
                      fontSize: "12px",
                      color: "#64748b",
                      marginBottom: "20px",
                    }}
                  >
                    Test proxy execution. Credentials are injected inside
                    Cloudflare V8 memory and scrubbed from responses.
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "180px 90px 1fr auto",
                      gap: "10px",
                      alignItems: "end",
                      marginBottom: "20px",
                    }}
                  >
                    <div>
                      <label
                        style={{
                          display: "block",
                          fontSize: "11px",
                          color: "#64748b",
                          marginBottom: "4px",
                          fontWeight: 600,
                        }}
                      >
                        Secret Alias
                      </label>
                      <select
                        aria-label="Secret Alias"
                        value={simAlias}
                        onChange={(e) => setSimAlias(e.target.value)}
                        style={{
                          width: "100%",
                          background: "#ffffff",
                          border: "1px solid #cbd5e1",
                          color: "#0f172a",
                          padding: "8px 10px",
                          borderRadius: "6px",
                          fontSize: "12px",
                        }}
                      >
                        {!policies.length && (
                          <option value="">No policies available</option>
                        )}
                        {policies.map((p) => (
                          <option key={p.alias} value={p.alias}>
                            {p.alias}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label
                        style={{
                          display: "block",
                          fontSize: "11px",
                          color: "#64748b",
                          marginBottom: "4px",
                          fontWeight: 600,
                        }}
                      >
                        Method
                      </label>
                      <select
                        value={simMethod}
                        onChange={(e) => setSimMethod(e.target.value)}
                        style={{
                          width: "100%",
                          background: "#ffffff",
                          border: "1px solid #cbd5e1",
                          color: "#0f172a",
                          padding: "8px 10px",
                          borderRadius: "6px",
                          fontSize: "12px",
                        }}
                      >
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                      </select>
                    </div>

                    <div>
                      <label
                        style={{
                          display: "block",
                          fontSize: "11px",
                          color: "#64748b",
                          marginBottom: "4px",
                          fontWeight: 600,
                        }}
                      >
                        Target URL
                      </label>
                      <input
                        type="text"
                        value={simUrl}
                        onChange={(e) => setSimUrl(e.target.value)}
                        style={{
                          width: "100%",
                          background: "#ffffff",
                          border: "1px solid #cbd5e1",
                          color: "#0f172a",
                          padding: "8px 10px",
                          borderRadius: "6px",
                          fontFamily: "monospace",
                          fontSize: "12px",
                        }}
                      />
                    </div>

                    <button
                      onClick={runSimulation}
                      disabled={
                        simLoading ||
                        !user ||
                        !policies.some((p) => p.alias === simAlias)
                      }
                      style={{
                        background: "#0f172a",
                        color: "#ffffff",
                        border: "none",
                        padding: "8px 18px",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: 600,
                        cursor: "pointer",
                        whiteSpace: "nowrap",
                      }}
                      className="btn-tactile"
                    >
                      {simLoading ? "Proxying..." : "Execute Blind Proxy"}
                    </button>
                  </div>

                  {simResult && (
                    <div
                      style={{
                        background: "#f8fafc",
                        border: "1px solid #e2e8f0",
                        borderRadius: "6px",
                        padding: "16px",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          marginBottom: "8px",
                          fontSize: "11px",
                        }}
                      >
                        <span style={{ color: "#059669", fontWeight: 700 }}>
                          {simResult.status
                            ? `HTTP ${simResult.status}`
                            : "Transport error"}
                        </span>
                        <span style={{ color: "#64748b" }}>
                          Redactions: {simResult.redactionsCount || 0}
                        </span>
                      </div>
                      {simResult.error && <p role="alert">{simResult.error}</p>}
                      <pre
                        style={{
                          color: "#0f172a",
                          fontFamily: "monospace",
                          fontSize: "12px",
                          overflowX: "auto",
                          background: "#ffffff",
                          padding: "12px",
                          borderRadius: "6px",
                          border: "1px solid #e2e8f0",
                        }}
                      >
                        {JSON.stringify(simResult.data, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {activeTab === "oauth" && (
                <section>
                  <h2>Authorize a companion</h2>
                  <p>
                    Run the companion login and approve only a request you
                    initiated. Headless devices use a confirmation code; CI uses
                    configured workload federation.
                  </p>
                  <pre>{`agentsecret login --server ${window.location.origin} --aliases API_TOKEN
agentsecret login --server ${window.location.origin} --device --aliases API_TOKEN`}</pre>
                  <p>
                    No OAuth token simulator or raw credential export is
                    available.
                  </p>
                </section>
              )}

              {/* TAB: AUDIT TRAIL */}
              {activeTab === "audit" && (
                <section
                  style={{
                    background: "#fff",
                    border: "1px solid #e2e8f0",
                    borderRadius: 8,
                    padding: 24,
                  }}
                >
                  <h3>Broker audit trail</h3>
                  <p>
                    Recent completed requests. Credentials, bodies and query
                    values are excluded.
                  </p>
                  <table
                    style={{ width: "100%", textAlign: "left", fontSize: 12 }}
                  >
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Alias</th>
                        <th>Domain</th>
                        <th>Method</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {auditLogs.map((log, i) => (
                        <tr key={i}>
                          <td>{log.at}</td>
                          <td>{log.alias}</td>
                          <td>{log.host}</td>
                          <td>{log.method}</td>
                          <td>{log.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!auditLogs.length && <p>No audit records are available.</p>}
                </section>
              )}

              {/* TAB: AGENT INTEGRATIONS */}
              {activeTab === "integrations" && (
                <section
                  style={{
                    background: "#fff",
                    border: "1px solid #e2e8f0",
                    borderRadius: 8,
                    padding: 24,
                  }}
                >
                  <h3>Connect an agent</h3>
                  <p>
                    Authorize the companion CLI with the aliases this agent may
                    use. The cloud broker supplies the tools; the companion
                    signs requests locally.
                  </p>
                  <pre
                    style={{ whiteSpace: "pre-wrap" }}
                  >{`agentsecret login --server ${window.location.origin} --aliases YOUR_ALIAS
agentsecret request --alias YOUR_ALIAS --url https://your-allowed-api.example/path`}</pre>
                  <button
                    onClick={() =>
                      copyToClipboard(
                        JSON.stringify(
                          {
                            mcpServers: {
                              agentsecret: {
                                command: "agentsecret",
                                args: [
                                  "mcp",
                                  "--server",
                                  window.location.origin,
                                ],
                              },
                            },
                          },
                          null,
                          2,
                        ),
                        "claude",
                      )
                    }
                  >
                    {copiedSnippet === "claude"
                      ? "Copied"
                      : "Copy stdio MCP configuration"}
                  </button>
                  <pre style={{ whiteSpace: "pre-wrap" }}>
                    {JSON.stringify(
                      {
                        mcpServers: {
                          agentsecret: {
                            command: "agentsecret",
                            args: ["mcp", "--server", window.location.origin],
                          },
                        },
                      },
                      null,
                      2,
                    )}
                  </pre>
                  <p>
                    The remote endpoint is{" "}
                    <code>{window.location.origin}/mcp</code>. Direct remote
                    clients must support PKCE and DPoP, with a registered
                    callback. A host plugin's private OAuth store is not shared
                    with this CLI.
                  </p>
                </section>
              )}
            </div>
          </main>
        </div>
      )}
    </div>
  );
}
