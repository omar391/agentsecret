import { useState } from "react";
import type { AppController } from "../../app/useAppController";
import { ConfirmDialog } from "../../ui/ConfirmDialog";

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
  const [pendingRevoke, setPendingRevoke] = useState<string | null>(null);
  return (
    <div className="card stack">
      <h3 className="h3" style={{ marginBottom: "8px" }}>
        Protected Local Executors and Grants
      </h3>
      <p className="subtle">
        Run <code>agentsecret browser identity</code> on the trusted Mac, then
        paste its public JSON below. Private keys never leave the dedicated
        Keychain item. Grants are short-lived and single-use. Browser execution
        remains disabled until the managed runtime is qualified.
      </p>
      <form onSubmit={handleApproveExecutor} className="form">
        <label className="field">
          Public executor identity JSON
          <textarea
            className="textarea"
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
          className="btn btn-primary"
          style={{ justifySelf: "start" }}
        >
          Approve public identity
        </button>
      </form>
      {executorFeedback && (
        <p className="notice notice-info" role="status">
          {executorFeedback}
        </p>
      )}
      <div className="stack-sm">
        <span className="label">Enrolled executors</span>
        {browserExecutors.length === 0 ? (
          <p className="empty-state">
            <strong>No enrolled executors.</strong>
            Approve a public identity above to enrol one.
          </p>
        ) : (
          <ul className="list">
            {browserExecutors.map((executor) => (
              <li key={executor.executorId} className="list-item">
                <span className="stack-sm" style={{ gap: 2, minWidth: 0 }}>
                  <code className="code-inline">{executor.executorId}</code>
                  <span className="subtle">
                    enrolled{" "}
                    {new Date(executor.enrolledAt * 1000).toLocaleString()}
                  </span>
                </span>
                <button
                  className="btn btn-danger btn-sm"
                  type="button"
                  onClick={() => setPendingRevoke(executor.executorId)}
                >
                  Revoke
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      {pendingRevoke && (
        <ConfirmDialog
          title="Revoke this executor?"
          body={
            <>
              <code className="code-inline">{pendingRevoke}</code> can no longer
              redeem grants. Outstanding grants for it are cancelled.
            </>
          }
          confirmLabel="Revoke executor"
          onCancel={() => setPendingRevoke(null)}
          onConfirm={() => handleRevokeExecutor(pendingRevoke)}
        />
      )}
      <form className="grid-2" onSubmit={handleIssueBrowserGrant}>
        <label className="field">
          Executor
          <select
            className="select"
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
        <label className="field">
          Secret alias
          <select
            className="select"
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
        <label className="field">
          Exact HTTPS origin
          <input
            className="input"
            aria-label="Protected action origin"
            value={grantOrigin}
            onChange={(event) => setGrantOrigin(event.target.value)}
            placeholder="https://app.example.com"
            required
          />
        </label>
        <label className="field">
          Actions (comma separated)
          <input
            className="input"
            aria-label="Protected action kinds"
            value={grantActions}
            onChange={(event) => setGrantActions(event.target.value)}
            placeholder="fill,totp"
            required
          />
        </label>
        <label className="field" style={{ gridColumn: "1 / -1" }}>
          Exact field selector
          <input
            className="input"
            aria-label="Protected action field selector"
            value={grantSelector}
            onChange={(event) => setGrantSelector(event.target.value)}
            placeholder="#password"
            required
          />
        </label>
        <button
          type="submit"
          className="btn btn-primary"
          style={{ justifySelf: "start" }}
        >
          Issue 60-second grant
        </button>
      </form>
      {grantFeedback && (
        <p className="notice notice-info" role="status">
          {grantFeedback}
        </p>
      )}
      {browserGrants.length > 0 && (
        <div>
          <div className="table-wrap">
            <table className="table">
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
                          className="btn btn-secondary btn-sm"
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
        </div>
      )}
    </div>
  );
}
