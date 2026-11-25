import type { AppController } from "../../app/useAppController";

export function ExecutorsGrantsPanel({ c }: { c: AppController }) {
  const {
    browserExecutors,
    browserGrants,
    executorApproval,
    executorFeedback,
    grantActions,
    grantAlias,
    grantExecutorId,
    grantFeedback,
    grantOrigin,
    grantSelector,
    handleApproveExecutor,
    handleIssueBrowserGrant,
    handleRevokeBrowserGrant,
    handleRevokeExecutor,
    policies,
    setExecutorApproval,
    setGrantActions,
    setGrantAlias,
    setGrantExecutorId,
    setGrantOrigin,
    setGrantSelector,
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
          marginBottom: "8px",
          color: "#0f172a",
        }}
      >
        Protected Local Executors and Grants
      </h3>
      <p style={{ color: "#64748b", fontSize: "12px" }}>
        Run <code>agentsecret browser identity</code> on the trusted Mac, then
        paste its public JSON below. Private keys never leave the dedicated
        Keychain item. Grants are short-lived and single-use. Browser execution
        remains disabled until the managed runtime is qualified.
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
            onChange={(event) => setExecutorApproval(event.target.value)}
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
                {new Date(executor.enrolledAt * 1000).toLocaleString()}{" "}
                <button
                  type="button"
                  onClick={() => void handleRevokeExecutor(executor.executorId)}
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
            onChange={(event) => setGrantExecutorId(event.target.value)}
            required
          >
            <option value="">Select an executor</option>
            {browserExecutors.map((executor) => (
              <option key={executor.executorId} value={executor.executorId}>
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
            onChange={(event) => setGrantAlias(event.target.value)}
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
            onChange={(event) => setGrantOrigin(event.target.value)}
            placeholder="https://app.example.com"
            required
          />
        </label>
        <label>
          Actions (comma separated)
          <input
            aria-label="Protected action kinds"
            value={grantActions}
            onChange={(event) => setGrantActions(event.target.value)}
            placeholder="fill,totp"
            required
          />
        </label>
        <label style={{ gridColumn: "1 / -1" }}>
          Exact field selector
          <input
            aria-label="Protected action field selector"
            value={grantSelector}
            onChange={(event) => setGrantSelector(event.target.value)}
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
                    {new Date(grant.expiresAt * 1000).toLocaleTimeString()}
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
                          void handleRevokeBrowserGrant(grant.grantId)
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
  );
}
