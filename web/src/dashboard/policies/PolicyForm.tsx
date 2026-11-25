import type { AppController } from "../../app/useAppController";

export function PolicyForm({ c }: { c: AppController }) {
  const {
    handleAddPolicy,
    newAlias,
    newDesc,
    newDomains,
    newFindLoginEnabled,
    newFindLoginFieldPath,
    newFindLoginTitle,
    newFindLoginUris,
    newFindLoginUsername,
    newInjectionType,
    newMethods,
    newSecretId,
    newSecretWriteCreate,
    newSecretWriteDelete,
    newSecretWriteUpdate,
    selectedConnectionId,
    setNewAlias,
    setNewDesc,
    setNewDomains,
    setNewFindLoginEnabled,
    setNewFindLoginFieldPath,
    setNewFindLoginTitle,
    setNewFindLoginUris,
    setNewFindLoginUsername,
    setNewInjectionType,
    setNewMethods,
    setNewSecretId,
    setNewSecretWriteCreate,
    setNewSecretWriteDelete,
    setNewSecretWriteUpdate,
    setSelectedConnectionId,
    vaultConnections,
  } = c;
  return (
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
              if (selectedConnection?.provider !== "onepassword-connect")
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
          Provider secret reference (Bitwarden UUID or item#/fields/field)
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
                event.target.value as "bearer" | "body_placeholder",
              )
            }
          >
            <option value="bearer">Authorization: Bearer header</option>
            <option value="body_placeholder">
              One explicit request-body placeholder
            </option>
          </select>
          {newInjectionType === "body_placeholder" && (
            <p style={{ margin: "6px 0 0", color: "#64748b" }}>
              Put exactly one <code>{"{{AGENTSECRET_SECRET}}"}</code> marker in
              each request body. Use `text/plain`, or put the marker in a JSON
              string value or JSON value slot (never a key or substring). The
              broker substitutes after authorizing the request.
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
              <legend style={{ fontSize: "12px", fontWeight: 700 }}>
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
                        setNewFindLoginUsername(event.target.value)
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
                        setNewFindLoginFieldPath(event.target.value)
                      }
                      maxLength={256}
                    />
                  </label>
                  <p style={{ gridColumn: "1 / -1", margin: 0 }}>
                    Lookup searches only this exact title. The login's username,
                    URL set, password field ID from the provider reference, and
                    optional label are checked before a result is returned.
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
              <legend style={{ fontSize: "12px", fontWeight: 700 }}>
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
              <label style={{ display: "block", marginTop: "6px" }}>
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
                Write access is separately requested at CLI login and bound to
                this alias. No selection means read-only.
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
              Agent vault writes are currently supported for 1Password Connect
              connections only.
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
  );
}
