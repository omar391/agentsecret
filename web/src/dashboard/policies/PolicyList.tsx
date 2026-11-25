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
            <th style={{ padding: "8px" }}>Credential placement</th>
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
                      Request body: one <code>{"{{AGENTSECRET_SECRET}}"}</code>
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
                      connection.provider === "onepassword-connect",
                  ) && p.secretId ? (
                    <button
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
                            setEditLoginEnabled(event.target.checked)
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
                                setEditLoginTitle(event.target.value)
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
                                setEditLoginUsername(event.target.value)
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
                                setEditLoginUris(event.target.value)
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
                                setEditLoginFieldPath(event.target.value)
                              }
                              maxLength={256}
                            />
                          </label>
                        </>
                      )}
                      <p>
                        Updating this policy invalidates existing agent grants.
                        Those agents must consent again.
                      </p>
                      <div>
                        <button type="submit">Save locator</button>{" "}
                        <button
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
  );
}
