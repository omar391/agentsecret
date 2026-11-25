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
    <div className="card">
      <h3 className="h3" style={{ marginBottom: "12px" }}>
        Register New Secret Alias Policy
      </h3>
      <form className="grid-2" onSubmit={handleAddPolicy}>
        <label className="field">
          Vault connection
          <select
            className="select"
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
        <label className="field">
          Provider secret reference (Bitwarden UUID or item#/fields/field)
          <input
            className="input"
            value={newSecretId}
            onChange={(e) => setNewSecretId(e.target.value)}
            placeholder="Provider reference"
          />
        </label>
        <div className="field">
          <label className="label" htmlFor="policy-alias">
            Secret Alias (e.g. AWS_DYNAMO)
          </label>
          <input
            id="policy-alias"
            className="input input-mono"
            type="text"
            value={newAlias}
            onChange={(e) => setNewAlias(e.target.value)}
            placeholder="MY_SERVICE_KEY"
            style={{ width: "100%" }}
          />
        </div>
        <div className="field">
          <label className="label" htmlFor="policy-domains">
            Allowed Domains (comma-separated)
          </label>
          <input
            id="policy-domains"
            className="input input-mono"
            type="text"
            value={newDomains}
            onChange={(e) => setNewDomains(e.target.value)}
            placeholder="api.service.com, *.service.com"
            style={{ width: "100%" }}
          />
        </div>
        <div className="field">
          <label className="label" htmlFor="policy-methods">
            Allowed HTTP Methods
          </label>
          <input
            id="policy-methods"
            className="input"
            type="text"
            value={newMethods}
            onChange={(e) => setNewMethods(e.target.value)}
            placeholder="GET, POST"
            style={{ width: "100%" }}
          />
        </div>
        <div className="field">
          <label className="label" htmlFor="policy-description">
            Description
          </label>
          <input
            id="policy-description"
            className="input"
            type="text"
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder="Brief description for LLM catalog"
            style={{ width: "100%" }}
          />
        </div>
        <label className="field" style={{ gridColumn: "1 / -1" }}>
          Credential placement
          <select
            className="select"
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
            <p className="muted">
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
            <fieldset className="fieldset">
              <legend style={{ fontSize: "12px", fontWeight: 700 }}>
                Owner-pinned Connect login lookup
              </legend>
              <label className="check">
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
                <div className="grid-2" style={{ marginTop: "10px" }}>
                  <label className="field">
                    Exact Connect item title
                    <input
                      className="input"
                      value={newFindLoginTitle}
                      onChange={(event) =>
                        setNewFindLoginTitle(event.target.value)
                      }
                      maxLength={128}
                      required
                    />
                  </label>
                  <label className="field">
                    Exact username
                    <input
                      className="input"
                      value={newFindLoginUsername}
                      onChange={(event) =>
                        setNewFindLoginUsername(event.target.value)
                      }
                      maxLength={512}
                      required
                    />
                  </label>
                  <label className="field" style={{ gridColumn: "1 / -1" }}>
                    Exact item URLs (one per line)
                    <textarea
                      className="textarea"
                      value={newFindLoginUris}
                      onChange={(event) =>
                        setNewFindLoginUris(event.target.value)
                      }
                      rows={3}
                      required
                    />
                  </label>
                  <label className="field">
                    Exact password field label (optional)
                    <input
                      className="input"
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
            <fieldset className="fieldset">
              <legend style={{ fontSize: "12px", fontWeight: 700 }}>
                Agent vault write grant
              </legend>
              <label className="check">
                <input
                  type="checkbox"
                  checked={newSecretWriteCreate}
                  onChange={(event) =>
                    setNewSecretWriteCreate(event.target.checked)
                  }
                />{" "}
                Allow creating a secret in this connection
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={newSecretWriteUpdate}
                  onChange={(event) =>
                    setNewSecretWriteUpdate(event.target.checked)
                  }
                />{" "}
                Allow updating this policy’s exact reference
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={newSecretWriteDelete}
                  onChange={(event) =>
                    setNewSecretWriteDelete(event.target.checked)
                  }
                />{" "}
                Allow deleting this policy’s exact reference
              </label>
              <p className="subtle">
                Write access is separately requested at CLI login and bound to
                this alias. No selection means read-only.
              </p>
            </fieldset>
          ) : (
            <p className="subtle">
              Agent vault writes are currently supported for 1Password Connect
              connections only.
            </p>
          )}
          <button
            type="submit"

            className="btn btn-primary btn-sm"
          >
            + Register Policy
          </button>
        </div>
      </form>
    </div>
  );
}
