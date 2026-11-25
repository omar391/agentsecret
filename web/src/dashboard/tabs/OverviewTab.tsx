import type { AppController } from "../../app/useAppController";
import { CheckCircle, Copy, Key } from "lucide-react";

export function OverviewTab({ c }: { c: AppController }) {
  const { copiedKey, copyToClipboard, policies, user } = c;
  return (
    <>
      {/* Gauge Cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "14px",
        }}
      >
        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "18px",
            boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
          }}
        >
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              color: "#64748b",
              fontWeight: 600,
            }}
          >
            Monthly Quota
          </div>
          <div
            style={{
              fontSize: "22px",
              fontWeight: 800,
              fontFamily: "monospace",
              color: "#0f172a",
              margin: "4px 0",
            }}
          >
            {user?.quotaUsed?.toLocaleString() ?? "0"} /{" "}
            {user?.quotaLimit?.toLocaleString() ?? "—"}
          </div>
          <div
            style={{
              height: "4px",
              background: "#e2e8f0",
              borderRadius: "2px",
              marginTop: "10px",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                width: `${Math.round(((user?.quotaUsed ?? 0) / (user?.quotaLimit || 1)) * 100)}%`,
                height: "100%",
                background: "#059669",
              }}
            />
          </div>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "18px",
            boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
          }}
        >
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              color: "#64748b",
              fontWeight: 600,
            }}
          >
            Configured Policies
          </div>
          <div
            style={{
              fontSize: "22px",
              fontWeight: 800,
              fontFamily: "monospace",
              color: "#2563eb",
              margin: "4px 0",
            }}
          >
            {policies.length} Active
          </div>
          <div
            style={{
              fontSize: "11px",
              color: "#059669",
              marginTop: "6px",
              fontWeight: 600,
            }}
          >
            Domain and method policies
          </div>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "18px",
            boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
          }}
        >
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              color: "#64748b",
              fontWeight: 600,
            }}
          >
            Database &amp; Vaults
          </div>
          <div
            style={{
              fontSize: "22px",
              fontWeight: 800,
              fontFamily: "monospace",
              color: "#4f46e5",
              margin: "4px 0",
            }}
          >
            SQLite DO
          </div>
          <div
            style={{
              fontSize: "11px",
              color: "#64748b",
              marginTop: "6px",
            }}
          >
            Server-side AES-256-GCM envelope
          </div>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "18px",
            boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
          }}
        >
          <div
            style={{
              fontSize: "11px",
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              color: "#64748b",
              fontWeight: 600,
            }}
          >
            Credential handling
          </div>
          <div
            style={{
              fontSize: "22px",
              fontWeight: 800,
              fontFamily: "monospace",
              color: "#059669",
              margin: "4px 0",
            }}
          >
            Strict broker
          </div>
          <div
            style={{
              fontSize: "11px",
              color: "#64748b",
              marginTop: "6px",
            }}
          >
            Volatile isolate RAM injection only
          </div>
        </div>
      </div>

      {/* Agent Bearer Key Panel */}
      <div
        style={{
          background: "#ffffff",
          border: "1px solid #e2e8f0",
          borderRadius: "8px",
          padding: "22px",
          boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "6px",
          }}
        >
          <h3
            style={{
              fontSize: "14px",
              fontWeight: 700,
              display: "flex",
              alignItems: "center",
              gap: "8px",
              color: "#0f172a",
            }}
          >
            <Key size={15} color="#059669" /> Companion authentication
          </h3>
          <span
            style={{
              fontSize: "11px",
              fontFamily: "monospace",
              color: "#059669",
              background: "#ecfdf5",
              padding: "2px 8px",
              borderRadius: "4px",
              fontWeight: 600,
            }}
          >
            DEVICE-BOUND SESSION
          </span>
        </div>
        <p
          style={{
            fontSize: "12px",
            color: "#64748b",
            marginBottom: "14px",
            lineHeight: 1.4,
          }}
        >
          Authorize the companion with explicit aliases. It stores a DPoP key in
          the operating-system credential store and signs each broker request.
        </p>
        <div style={{ display: "flex", gap: "8px" }}>
          <input
            type="text"
            readOnly
            value={"agentsecret login --server " + window.location.origin}
            style={{
              flex: 1,
              background: "#f8fafc",
              border: "1px solid #cbd5e1",
              color: "#0f172a",
              padding: "9px 12px",
              borderRadius: "6px",
              fontFamily: "monospace",
              fontSize: "12px",
            }}
          />
          <button
            onClick={() =>
              copyToClipboard(
                "agentsecret login --server " + window.location.origin,
                "apiKey",
              )
            }
            style={{
              background: copiedKey ? "#059669" : "#0f172a",
              color: "#ffffff",
              border: "none",
              padding: "9px 16px",
              borderRadius: "6px",
              fontSize: "12px",
              fontWeight: 600,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "6px",
            }}
            className="btn-tactile"
          >
            {copiedKey ? <CheckCircle size={14} /> : <Copy size={14} />}{" "}
            {copiedKey ? "Copied" : "Copy"}
          </button>
        </div>
      </div>
    </>
  );
}
