import React, { useState, useEffect, useRef } from "react";
import {
  ViewMode,
  DashboardTab,
  DASHBOARD_TABS,
  UserSession,
  VaultConnection,
  ProviderMode,
  PrivateInputRequest,
  ProviderCapability,
} from "./types";

export function useAppController() {
  const [view, setView] = useState<ViewMode>("landing");
  const [activeTab, setActiveTab] = useState<DashboardTab>("overview");
  const [user, setUser] = useState<UserSession | null>(null);
  const [isLoadingUser, setIsLoadingUser] = useState(true);
  // Empty states wait for the first load after sign-in instead of flashing "none yet".
  const [policiesLoaded, setPoliciesLoaded] = useState(false);
  const [vaultConnectionsLoaded, setVaultConnectionsLoaded] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
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

  // Keep the view and tab in the URL so refresh and back keep position. The
  // first run is skipped so the initial URL is read before it is rewritten.
  const urlSyncReady = useRef(false);
  useEffect(() => {
    setSidebarOpen(false);
    if (!urlSyncReady.current) {
      urlSyncReady.current = true;
      return;
    }
    const history = window.history;
    if (!history || typeof history.replaceState !== "function") return;
    const params = new URLSearchParams(window.location.search);
    params.set("view", view);
    if (view === "dashboard") params.set("tab", activeTab);
    else params.delete("tab");
    params.delete("auth");
    history.replaceState(
      null,
      "",
      window.location.pathname + "?" + params.toString(),
    );
  }, [view, activeTab]);

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
    setPoliciesLoaded(true);
  };
  const refreshVaultConnections = async (signal?: AbortSignal) => {
    const res = await fetch("/api/user/vault-connections", { signal });
    if (!res.ok) throw new Error("Unable to load vault connections");
    const data = await res.json();
    if (signal?.aborted) return;
    setVaultConnections(data.connections);
    setVaultConnectionsLoaded(true);
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
    setPoliciesLoaded(false);
    setVaultConnectionsLoaded(false);
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

  const handleRevokeAllSessions = async () => {
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

  return {
    view,
    setView,
    activeTab,
    setActiveTab,
    user,
    setUser,
    isLoadingUser,
    policiesLoaded,
    vaultConnectionsLoaded,
    setIsLoadingUser,
    sidebarOpen,
    setSidebarOpen,
    handleRevokeAllSessions,
    showAuthModal,
    setShowAuthModal,
    onboardingName,
    setOnboardingName,
    onboardingStatus,
    setOnboardingStatus,
    copiedKey,
    setCopiedKey,
    copiedSnippet,
    setCopiedSnippet,
    vaultProvider,
    setVaultProvider,
    bwsToken,
    setBwsToken,
    companionProfileId,
    setCompanionProfileId,
    serviceAccountVaultId,
    setServiceAccountVaultId,
    opToken,
    setOpToken,
    connectUrl,
    setConnectUrl,
    connectVault,
    setConnectVault,
    vaultSaveStatus,
    setVaultSaveStatus,
    vaultConnections,
    setVaultConnections,
    providerModes,
    setProviderModes,
    connectionAlias,
    setConnectionAlias,
    replaceConnectionId,
    setReplaceConnectionId,
    selectedConnectionId,
    setSelectedConnectionId,
    saveConnectionId,
    setSaveConnectionId,
    saveMode,
    setSaveMode,
    deleteConfirmed,
    setDeleteConfirmed,
    saveTitle,
    setSaveTitle,
    saveReference,
    setSaveReference,
    saveValue,
    setSaveValue,
    saveOperationId,
    setSaveOperationId,
    saveStatus,
    setSaveStatus,
    compareStatus,
    setCompareStatus,
    ensureStatus,
    setEnsureStatus,
    savedReference,
    setSavedReference,
    saveInFlight,
    compareRequestVersion,
    privateInputRequests,
    setPrivateInputRequests,
    privateInputNextCursor,
    setPrivateInputNextCursor,
    privateInputLoadingMore,
    setPrivateInputLoadingMore,
    privateInputPaginationStarted,
    privateInputDrafts,
    setPrivateInputDrafts,
    privateInputSubmitting,
    setPrivateInputSubmitting,
    privateInputFeedback,
    setPrivateInputFeedback,
    findConnectionId,
    setFindConnectionId,
    findReference,
    setFindReference,
    findStatus,
    setFindStatus,
    findResult,
    setFindResult,
    findRequestVersion,
    handleLoadMorePrivateInputs,
    clearVaultCredentialDraft,
    newAlias,
    setNewAlias,
    newDomains,
    setNewDomains,
    newMethods,
    setNewMethods,
    newInjectionType,
    setNewInjectionType,
    newDesc,
    setNewDesc,
    newSecretId,
    setNewSecretId,
    newFindLoginEnabled,
    setNewFindLoginEnabled,
    newFindLoginTitle,
    setNewFindLoginTitle,
    newFindLoginUsername,
    setNewFindLoginUsername,
    newFindLoginUris,
    setNewFindLoginUris,
    newFindLoginFieldPath,
    setNewFindLoginFieldPath,
    newSecretWriteCreate,
    setNewSecretWriteCreate,
    newSecretWriteUpdate,
    setNewSecretWriteUpdate,
    newSecretWriteDelete,
    setNewSecretWriteDelete,
    editingLoginAlias,
    setEditingLoginAlias,
    editLoginEnabled,
    setEditLoginEnabled,
    editLoginTitle,
    setEditLoginTitle,
    editLoginUsername,
    setEditLoginUsername,
    editLoginUris,
    setEditLoginUris,
    editLoginFieldPath,
    setEditLoginFieldPath,
    policies,
    setPolicies,
    executorApproval,
    setExecutorApproval,
    executorFeedback,
    setExecutorFeedback,
    browserExecutors,
    setBrowserExecutors,
    browserGrants,
    setBrowserGrants,
    grantExecutorId,
    setGrantExecutorId,
    grantAlias,
    setGrantAlias,
    grantOrigin,
    setGrantOrigin,
    grantActions,
    setGrantActions,
    grantSelector,
    setGrantSelector,
    grantFeedback,
    setGrantFeedback,
    refreshExecutorState,
    simAlias,
    setSimAlias,
    simUrl,
    setSimUrl,
    simMethod,
    setSimMethod,
    simLoading,
    setSimLoading,
    simResult,
    setSimResult,
    dashboardNotice,
    setDashboardNotice,
    auditLogs,
    setAuditLogs,
    openFaq,
    setOpenFaq,
    checkAuthSession,
    startSocialLogin,
    handleOnboarding,
    refreshPolicies,
    refreshVaultConnections,
    handleLogout,
    copyToClipboard,
    handleSaveVault,
    handleSaveSecret,
    handleCompareSecret,
    handleEnsureSecret,
    handleFulfillPrivateInput,
    handleFindSecret,
    handleAddPolicy,
    handleUpdateLoginLocator,
    handleApproveExecutor,
    handleIssueBrowserGrant,
    handleRevokeBrowserGrant,
    handleRevokeExecutor,
    runSimulation,
  };
}

export type AppController = ReturnType<typeof useAppController>;
