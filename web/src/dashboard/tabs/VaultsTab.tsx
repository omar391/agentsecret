import type { AppController } from "../../app/useAppController";
import { PROVIDER_MODE_LABELS, ReleaseProviderMode } from "../../app/types";
import { useState } from "react";
import { CheckCircle } from "lucide-react";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { PageHeader } from "../PageHeader";

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
  const [pendingDisconnect, setPendingDisconnect] = useState<{
    id: string;
    alias: string;
  } | null>(null);
  const disconnect = async (id: string) => {
    try {
      const res = await fetch(
        `/api/user/vault-connections?id=${encodeURIComponent(id)}`,
        { method: "DELETE" },
      );
      if (!res.ok) throw new Error();
      await refreshVaultConnections();
      await refreshPolicies();
    } catch {
      setDashboardNotice(
        "Connection could not be disconnected. Rebind affected policies to continue.",
      );
    }
  };
  return (
    <>
      <PageHeader
        title="Vault Connections"
        description="Connect the vaults AgentSecret may read from. Credentials are encrypted before they are stored."
      />
      <div className="card">
        <div style={{ marginBottom: "18px" }}>
          <h2 className="card-title">
            {replaceConnectionId
              ? "Replace connection credentials"
              : "Add a vault connection"}
          </h2>
          <p className="card-desc">
            Cloud tokens entered here travel over HTTPS to the trusted broker,
            which encrypts them with a separate AES-GCM key before storing them
            in the tenant authority. Service-account tokens and password-manager
            profiles stay in the local Keychain; this page receives only safe
            identifiers.
          </p>
        </div>

        <section className="card-flat" aria-label="Provider availability">
          <h4 className="h3">Provider availability</h4>
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

        <form className="stack" onSubmit={handleSaveVault}>
          <label className="field">
            Connection name
            <input
              className="input"
              value={connectionAlias}
              onChange={(e) => setConnectionAlias(e.target.value)}
              maxLength={64}
              required
              autoComplete="off"
              placeholder="work"
            />
          </label>
          <div>
            <label className="field">
              Select Password Manager / Secrets Engine
            </label>
            <select
              className="select"
              value={vaultProvider}
              onChange={(e) => setVaultProvider(e.target.value as any)}
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
            <div className="card-flat">
              <div className="label">
                Bitwarden Secrets Manager Configuration
              </div>
              <label className="field">
                BWS Access Token (format:
                0.&lt;clientId&gt;.&lt;clientSecret&gt;:&lt;seedBase64&gt;)
              </label>
              <input
                className="input input-mono"
                type="password"
                value={bwsToken}
                onChange={(e) => setBwsToken(e.target.value)}
                placeholder="0.2a8f...:base64seed=="
              />
            </div>
          )}

          {vaultSaveStatus === "error" && (
            <p className="notice notice-error" role="alert">
              Vault connection was not saved. Verify the configuration and
              server keyring.
            </p>
          )}
          {["bitwarden_password", "lastpass"].includes(vaultProvider) && (
            <div className="card-flat">
              <div className="label">Local companion profile</div>
              <label className="field">Profile ID</label>
              <input
                className="input input-mono"
                type="text"
                value={companionProfileId}
                onChange={(e) => setCompanionProfileId(e.target.value)}
                placeholder="bitwarden-work or lastpass-test"
              />
            </div>
          )}

          {vaultProvider === "onepassword_service_account" && (
            <label className="field">
              1Password vault ID
              <input
                className="input"
                value={serviceAccountVaultId}
                onChange={(e) => setServiceAccountVaultId(e.target.value)}
                required
                autoComplete="off"
              />
            </label>
          )}
          {vaultProvider === "onepassword" && replaceConnectionId && (
            <>
              <label className="field">
                1Password Connect access token
                <input
                  className="input"
                  type="password"
                  value={opToken}
                  onChange={(e) => setOpToken(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                Connect server HTTPS URL
                <input
                  className="input"
                  type="url"
                  value={connectUrl}
                  onChange={(e) => setConnectUrl(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                Vault ID
                <input
                  className="input"
                  value={connectVault}
                  onChange={(e) => setConnectVault(e.target.value)}
                  required
                />
              </label>
            </>
          )}
          <button
            type="submit"
            style={{ alignSelf: "flex-start" }}
            className="btn btn-primary"
          >
            {replaceConnectionId
              ? "Replace Connection Credentials"
              : "Encrypt & Create Vault Connection"}
          </button>
        </form>

        {vaultSaveStatus === "success" && (
          <div className="notice notice-success" style={{ marginTop: 16 }}>
            <CheckCircle size={15} /> Vault connection encrypted with the
            separate server keyring and saved.
          </div>
        )}
      </div>
      <section className="card stack" aria-label="Connected vaults">
        <div>
          <h2 className="card-title">Connected vaults</h2>
          <p className="card-desc">
            Each connection keeps a revision. Policies are bound to the revision
            they were saved against.
          </p>
        </div>
        {vaultConnections.length === 0 ? (
          <p className="empty-state">
            <strong>No vault connections yet.</strong>
            Add one above to start binding secret aliases.
          </p>
        ) : (
          <ul className="list">
            {vaultConnections.map((connection) => (
              <li key={connection.id} className="list-item">
                <div className="stack-sm" style={{ gap: 4, minWidth: 0 }}>
                  <span className="row" style={{ gap: 8 }}>
                    <strong className="break">{connection.alias}</strong>
                    <span className="badge">{connection.provider}</span>
                    <span className="badge">rev {connection.revision}</span>
                  </span>
                  <span className="subtle">
                    {connection.capabilities
                      ? `${connection.capabilities.read ? "read" : "no read"}; ${connection.capabilities.create || connection.capabilities.update ? "write available" : "save unavailable"}`
                      : "capabilities unavailable"}
                  </span>
                </div>
                <div className="row" style={{ gap: 8 }}>
                  <button
                    className="btn btn-secondary btn-sm"
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
                    className="btn btn-danger btn-sm"
                    type="button"
                    onClick={() =>
                      setPendingDisconnect({
                        id: connection.id,
                        alias: connection.alias,
                      })
                    }
                  >
                    Disconnect
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
        <p className="notice notice-info" role="status">
          Replacing or disconnecting a connection disables policies bound to its
          prior revision until they are saved again.
        </p>
      </section>
      {pendingDisconnect && (
        <ConfirmDialog
          title={"Disconnect " + pendingDisconnect.alias + "?"}
          body="Policies bound to this connection stop working until they are rebound. The stored provider credentials are deleted from the broker."
          confirmLabel="Disconnect vault"
          onCancel={() => setPendingDisconnect(null)}
          onConfirm={() => disconnect(pendingDisconnect.id)}
        />
      )}
    </>
  );
}
