import type { AppController } from "../../app/useAppController";
import { PageHeader } from "../PageHeader";

export function SimulatorTab({ c }: { c: AppController }) {
  const {
    policies,
    runSimulation,
    setSimAlias,
    setSimMethod,
    setSimUrl,
    simAlias,
    simLoading,
    simMethod,
    simResult,
    simUrl,
    user,
  } = c;
  const status = simResult?.status;
  const statusClass = !status
    ? "badge badge-danger"
    : status >= 200 && status < 300
      ? "badge badge-success"
      : status >= 400 && status < 500
        ? "badge badge-warn"
        : "badge badge-danger";
  return (
    <>
      <PageHeader
        title="Egress Simulator"
        description="Test proxy execution. Credentials are injected inside the broker and scrubbed from responses."
      />
      <section className="card stack">
        <form
          className="form-grid"
          style={{ alignItems: "end" }}
          onSubmit={(event) => {
            event.preventDefault();
            void runSimulation();
          }}
        >
          <div className="field">
            <label className="label" htmlFor="sim-alias">
              Secret Alias
            </label>
            <select
              id="sim-alias"
              className="select"
              aria-label="Secret Alias"
              value={simAlias}
              onChange={(e) => setSimAlias(e.target.value)}
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
          <div className="field">
            <label className="label" htmlFor="sim-method">
              Method
            </label>
            <select
              id="sim-method"
              className="select"
              value={simMethod}
              onChange={(e) => setSimMethod(e.target.value)}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </div>
          <div className="field span-all">
            <label className="label" htmlFor="sim-url">
              Target URL
            </label>
            <input
              id="sim-url"
              className="input input-mono"
              type="text"
              value={simUrl}
              onChange={(e) => setSimUrl(e.target.value)}
            />
          </div>
          <div className="form-actions span-all">
            <button
              type="button"
              onClick={runSimulation}
              disabled={
                simLoading ||
                !user ||
                !policies.some((p) => p.alias === simAlias)
              }
              className="btn btn-primary"
            >
              {simLoading ? "Proxying..." : "Execute Blind Proxy"}
            </button>
            {!policies.length && (
              <span className="subtle">
                Register a policy first to choose an alias.
              </span>
            )}
          </div>
        </form>

        {simResult && (
          <div className="card-flat stack-sm" aria-live="polite">
            <div className="row-between">
              <span className={statusClass}>
                {simResult.status
                  ? `HTTP ${simResult.status}`
                  : "Transport error"}
              </span>
              <span className="subtle">
                Redactions: {simResult.redactionsCount || 0}
              </span>
            </div>
            {simResult.error && (
              <p className="notice notice-error" role="alert">
                {simResult.error}
              </p>
            )}
            {simResult.data !== undefined && (
              <pre className="code-block">
                {JSON.stringify(simResult.data, null, 2)}
              </pre>
            )}
          </div>
        )}
      </section>
    </>
  );
}
