import type { AppController } from "../app/useAppController";

export function HowItWorks({ c }: { c: AppController }) {
  void c;
  return (
    <section
      id="how-it-works"
      style={{
        maxWidth: "1080px",
        margin: "50px auto",
        padding: "0 24px",
        width: "100%",
      }}
    >
      <div style={{ textAlign: "center", marginBottom: "40px" }}>
        <div
          style={{
            fontSize: "11px",
            fontFamily: "monospace",
            color: "#2563eb",
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
            marginBottom: "8px",
          }}
        >
          Simple 3-Step Architecture
        </div>
        <h2
          style={{
            fontSize: "32px",
            fontWeight: 800,
            letterSpacing: "-0.03em",
            color: "#0f172a",
          }}
        >
          How AgentSecret Works
        </h2>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: "20px",
        }}
      >
        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "24px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
          }}
        >
          <div
            style={{
              width: "32px",
              height: "32px",
              borderRadius: "50%",
              background: "#eff6ff",
              color: "#2563eb",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 800,
              fontSize: "14px",
              marginBottom: "14px",
            }}
          >
            1
          </div>
          <h4
            style={{
              fontSize: "16px",
              fontWeight: 700,
              color: "#0f172a",
              marginBottom: "8px",
            }}
          >
            Connect Your Vault
          </h4>
          <p
            style={{
              fontSize: "13px",
              color: "#64748b",
              lineHeight: 1.5,
            }}
          >
            Connect Bitwarden Secrets Manager directly, or bind a Bitwarden
            Password Manager, 1Password service account, or LastPass companion
            locally. The broker encrypts cloud connection metadata at rest with
            AES-256-GCM.
          </p>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "24px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
          }}
        >
          <div
            style={{
              width: "32px",
              height: "32px",
              borderRadius: "50%",
              background: "#ecfdf5",
              color: "#059669",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 800,
              fontSize: "14px",
              marginBottom: "14px",
            }}
          >
            2
          </div>
          <h4
            style={{
              fontSize: "16px",
              fontWeight: 700,
              color: "#0f172a",
              marginBottom: "8px",
            }}
          >
            Define Whitelist Policies
          </h4>
          <p
            style={{
              fontSize: "13px",
              color: "#64748b",
              lineHeight: 1.5,
            }}
          >
            Map secret aliases to strict target domains and HTTP methods (e.g.{" "}
            <code>GITHUB_API</code> can only communicate with{" "}
            <code>api.github.com</code>).
          </p>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "24px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
          }}
        >
          <div
            style={{
              width: "32px",
              height: "32px",
              borderRadius: "50%",
              background: "#f5f3ff",
              color: "#7c3aed",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 800,
              fontSize: "14px",
              marginBottom: "14px",
            }}
          >
            3
          </div>
          <h4
            style={{
              fontSize: "16px",
              fontWeight: 700,
              color: "#0f172a",
              marginBottom: "8px",
            }}
          >
            Point Your Agents
          </h4>
          <p
            style={{
              fontSize: "13px",
              color: "#64748b",
              lineHeight: 1.5,
            }}
          >
            Use the authenticated companion with an agent that supports local
            stdio MCP. The cloud returns bounded API results; it does not
            execute a native command on your device.
          </p>
        </div>
      </div>
    </section>
  );
}
