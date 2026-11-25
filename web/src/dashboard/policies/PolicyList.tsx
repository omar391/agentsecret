import React from "react";
import type { AppController } from "../../app/useAppController";

export function PolicyList({ c }: { c: AppController }) {
  const {
    editLoginEnabled,
    editLoginFieldPath,
    editLoginTitle,
    editLoginUris,
    editLoginUsername,
    editingLoginAlias,
    handleUpdateLoginLocator,
    policies,
    setEditLoginEnabled,
    setEditLoginFieldPath,
    setEditLoginTitle,
    setEditLoginUris,
    setEditLoginUsername,
    setEditingLoginAlias,
    vaultConnections,
  } = c;
  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h2 className="card-title">Active Whitelisted Policies</h2>
          <p className="card-desc">
            Each alias may reach only its listed domains with its listed
            methods.
          </p>
        </div>
        <span className="badge">{policies.length} total</span>
      </div>
      {policies.length === 0 ? (
        <p className="empty-state">
          <strong>No policies yet.</strong>
          Register an alias above to let an agent reach one approved API.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr style={{ textAlign: "left" }}>
                <th>Alias</th>
                <th>Target Domains</th>
                <th>Methods</th>
                <th>Credential placement</th>
                <th>Description</th>
                <th>Firewall</th>
                <th>Locator</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <React.Fragment key={p.alias}>
                  <tr>
                    <td>{p.alias}</td>
                    <td>
                      <code>{p.domains}</code>
                    </td>
                    <td>{p.methods}</td>
                    <td>
                      {p.injectionType === "body_placeholder" ? (
                        <>
                          Request body: one{" "}
                          <code>{"{{AGENTSECRET_SECRET}}"}</code>
                        </>
                      ) : (
                        p.injectionType || "bearer"
                      )}
                    </td>
                    <td>{p.desc}</td>
                    <td>✓ Whitelisted</td>
                    <td>
                      {vaultConnections.some(
                        (connection) =>
                          connection.id === p.connectionId &&
                          connection.provider === "onepassword-connect",
                      ) && p.secretId ? (
                        <button
                          className="btn btn-secondary btn-sm"
                          type="button"
                          onClick={() => {
                            setEditingLoginAlias(p.alias);
                            const selector = p.findSelector;
                            const enabled = selector?.kind === "login_lookup";
                            setEditLoginEnabled(enabled);
                            setEditLoginTitle(enabled ? selector.title : "");
                            setEditLoginUsername(
                              enabled ? selector.username || "" : "",
                            );
                            setEditLoginUris(
                              enabled ? (selector.uris || []).join("\n") : "",
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
                      <td colSpan={7}>
                        <form
                          aria-label={`Edit login lookup ${p.alias}`}
                          onSubmit={handleUpdateLoginLocator}
                          style={{ display: "grid", gap: "8px" }}
                        >
                          <label className="check">
                            <input
                              type="checkbox"
                              checked={editLoginEnabled}
                              onChange={(event) =>
                                setEditLoginEnabled(event.target.checked)
                              }
                            />{" "}
                            Enable this exact login lookup
                          </label>
                          {editLoginEnabled && (
                            <>
                              <label className="field">
                                Exact Connect item title
                                <input
                                  className="input"
                                  value={editLoginTitle}
                                  onChange={(event) =>
                                    setEditLoginTitle(event.target.value)
                                  }
                                  maxLength={128}
                                  required
                                />
                              </label>
                              <label className="field">
                                Exact username
                                <input
                                  className="input"
                                  value={editLoginUsername}
                                  onChange={(event) =>
                                    setEditLoginUsername(event.target.value)
                                  }
                                  maxLength={512}
                                  required
                                />
                              </label>
                              <label className="field">
                                Exact item URLs (one per line)
                                <textarea
                                  className="textarea"
                                  value={editLoginUris}
                                  onChange={(event) =>
                                    setEditLoginUris(event.target.value)
                                  }
                                  rows={3}
                                  required
                                />
                              </label>
                              <label className="field">
                                Exact password field label (optional)
                                <input
                                  className="input"
                                  value={editLoginFieldPath}
                                  onChange={(event) =>
                                    setEditLoginFieldPath(event.target.value)
                                  }
                                  maxLength={256}
                                />
                              </label>
                            </>
                          )}
                          <p>
                            Updating this policy invalidates existing agent
                            grants. Those agents must consent again.
                          </p>
                          <div>
                            <button
                              className="btn btn-secondary btn-sm"
                              type="submit"
                            >
                              Save locator
                            </button>{" "}
                            <button
                              className="btn btn-secondary btn-sm"
                              type="button"
                              onClick={() => setEditingLoginAlias(null)}
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
      )}
    </div>
  );
}
