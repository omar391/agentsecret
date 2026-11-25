import type { AppController } from "../../app/useAppController";
import { PROVIDER_MODE_LABELS, ReleaseProviderMode } from "../../app/types";
import { CheckCircle } from "lucide-react";

export function VaultsTab({ c }: { c: AppController }) {
  const {
    bwsToken,
    clearVaultCredentialDraft,
    companionProfileId,
    connectUrl,
    connectVault,
    connectionAlias,
    handleSaveVault,
    opToken,
    providerModes,
    refreshPolicies,
    refreshVaultConnections,
    replaceConnectionId,
    serviceAccountVaultId,
    setBwsToken,
    setCompanionProfileId,
    setConnectUrl,
    setConnectVault,
    setConnectionAlias,
    setDashboardNotice,
    setOpToken,
    setReplaceConnectionId,
    setServiceAccountVaultId,
    setVaultProvider,
    vaultConnections,
    vaultProvider,
    vaultSaveStatus,
  } = c;
  return (
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
          Cloud tokens entered here travel over HTTPS to the trusted broker,
          which encrypts them with a separate AES-GCM key before storing them in
          the tenant authority. Service-account tokens and password-manager
          profiles stay in the local Keychain; this page receives only safe
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
          {(Object.keys(PROVIDER_MODE_LABELS) as ReleaseProviderMode[]).map(
            (mode) => {
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
                  <span aria-label={availability}>{availability}</span>
                  {capability?.reason ? (
                    <span> {capability.reason}</span>
                  ) : null}
                </li>
              );
            },
          )}
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
            onChange={(e) => setVaultProvider(e.target.value as any)}
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
            <option value="lastpass">LastPass (local companion)</option>
            {replaceConnectionId && vaultProvider === "onepassword" && (
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
            Vault connection was not saved. Verify the configuration and server
            keyring.
          </p>
        )}
        {["bitwarden_password", "lastpass"].includes(vaultProvider) && (
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
              onChange={(e) => setCompanionProfileId(e.target.value)}
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
              onChange={(e) => setServiceAccountVaultId(e.target.value)}
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
          <CheckCircle size={15} /> Vault connection encrypted with the separate
          server keyring and saved.
        </div>
      )}
      <section aria-label="Connected vaults" style={{ marginTop: "20px" }}>
        <h4>Connected vaults</h4>
        {vaultConnections.length === 0 ? (
          <p>No vault connections yet.</p>
        ) : (
          <ul>
            {vaultConnections.map((connection) => (
              <li key={connection.id}>
                {connection.alias} · {connection.provider} · revision{" "}
                {connection.revision} ·{" "}
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
                        : connection.provider === "bitwarden-password-manager"
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
          Replacing or disconnecting a connection disables policies bound to its
          prior revision until they are saved again.
        </p>
      </section>
    </div>
  );
}
