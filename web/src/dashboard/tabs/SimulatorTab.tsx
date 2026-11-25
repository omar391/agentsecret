import type { AppController } from "../../app/useAppController";

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
      <h3
        style={{
          fontSize: "16px",
          fontWeight: 800,
          marginBottom: "6px",
          color: "#0f172a",
        }}
      >
        In-Dashboard Egress Simulator
      </h3>
      <p
        style={{
          fontSize: "12px",
          color: "#64748b",
          marginBottom: "20px",
        }}
      >
        Test proxy execution. Credentials are injected inside Cloudflare V8
        memory and scrubbed from responses.
      </p>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "180px 90px 1fr auto",
          gap: "10px",
          alignItems: "end",
          marginBottom: "20px",
        }}
      >
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
            Secret Alias
          </label>
          <select
            aria-label="Secret Alias"
            value={simAlias}
            onChange={(e) => setSimAlias(e.target.value)}
            style={{
              width: "100%",
              background: "#ffffff",
              border: "1px solid #cbd5e1",
              color: "#0f172a",
              padding: "8px 10px",
              borderRadius: "6px",
              fontSize: "12px",
            }}
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
            Method
          </label>
          <select
            value={simMethod}
            onChange={(e) => setSimMethod(e.target.value)}
            style={{
              width: "100%",
              background: "#ffffff",
              border: "1px solid #cbd5e1",
              color: "#0f172a",
              padding: "8px 10px",
              borderRadius: "6px",
              fontSize: "12px",
            }}
          >
            <option value="GET">GET</option>
            <option value="POST">POST</option>
          </select>
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
            Target URL
          </label>
          <input
            type="text"
            value={simUrl}
            onChange={(e) => setSimUrl(e.target.value)}
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

        <button
          onClick={runSimulation}
          disabled={
            simLoading || !user || !policies.some((p) => p.alias === simAlias)
          }
          style={{
            background: "#0f172a",
            color: "#ffffff",
            border: "none",
            padding: "8px 18px",
            borderRadius: "6px",
            fontSize: "12px",
            fontWeight: 600,
            cursor: "pointer",
            whiteSpace: "nowrap",
          }}
          className="btn-tactile"
        >
          {simLoading ? "Proxying..." : "Execute Blind Proxy"}
        </button>
      </div>

      {simResult && (
        <div
          style={{
            background: "#f8fafc",
            border: "1px solid #e2e8f0",
            borderRadius: "6px",
            padding: "16px",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "8px",
              fontSize: "11px",
            }}
          >
            <span style={{ color: "#059669", fontWeight: 700 }}>
              {simResult.status
                ? `HTTP ${simResult.status}`
                : "Transport error"}
            </span>
            <span style={{ color: "#64748b" }}>
              Redactions: {simResult.redactionsCount || 0}
            </span>
          </div>
          {simResult.error && <p role="alert">{simResult.error}</p>}
          <pre
            style={{
              color: "#0f172a",
              fontFamily: "monospace",
              fontSize: "12px",
              overflowX: "auto",
              background: "#ffffff",
              padding: "12px",
              borderRadius: "6px",
              border: "1px solid #e2e8f0",
            }}
          >
            {JSON.stringify(simResult.data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
