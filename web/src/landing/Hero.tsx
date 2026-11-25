import type { AppController } from "../app/useAppController";
import { ArrowRight, Play } from "lucide-react";

export function Hero({ c }: { c: AppController }) {
  const { setShowAuthModal, setView, user } = c;
  return (
    <section
      style={{
        maxWidth: "1080px",
        margin: "0 auto",
        padding: "80px 24px 60px 24px",
        textAlign: "center",
      }}
    >
      {/* Status Pill */}
      <div
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "8px",
          background: "#ecfdf5",
          border: "1px solid #a7f3d0",
          borderRadius: "20px",
          padding: "4px 14px",
          marginBottom: "24px",
        }}
      >
        <div
          style={{
            width: "6px",
            height: "6px",
            borderRadius: "50%",
            background: "#059669",
          }}
        />
        <span
          style={{
            fontSize: "11px",
            fontFamily: "monospace",
            color: "#059669",
            textTransform: "uppercase",
            letterSpacing: "0.04em",
            fontWeight: 700,
          }}
        >
          Policy-bound secret broker
        </span>
      </div>

      {/* Magnetic Value Proposition Headline */}
      <h1
        style={{
          fontSize: "54px",
          fontWeight: 800,
          letterSpacing: "-0.04em",
          lineHeight: 1.12,
          color: "#0f172a",
          maxWidth: "880px",
          margin: "0 auto 20px auto",
        }}
      >
        Give agents approved API access through secret aliases.
      </h1>

      {/* Acute Pain Point Subhead */}
      <p
        style={{
          fontSize: "19px",
          color: "#475569",
          lineHeight: 1.6,
          maxWidth: "740px",
          margin: "0 auto 36px auto",
        }}
      >
        AgentSecret uses <strong>Bitwarden Secrets Manager</strong>,{" "}
        <strong>1Password service accounts</strong>, or an owner-bound local
        password-manager companion. Agents receive scoped results through
        aliases. The operator, broker, device, companion, and approved upstream
        remain trust boundaries.
      </p>

      {/* High-Converting Funnel CTAs */}
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          gap: "14px",
          flexWrap: "wrap",
          marginBottom: "40px",
        }}
      >
        <button
          onClick={() => {
            if (user) {
              setView("dashboard");
            } else {
              setShowAuthModal(true);
            }
          }}
          style={{
            background: "#0f172a",
            color: "#ffffff",
            border: "none",
            padding: "14px 28px",
            borderRadius: "6px",
            fontSize: "15px",
            fontWeight: 600,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}
          className="btn-tactile"
        >
          Start Securing Agents Free <ArrowRight size={17} />
        </button>

        <a
          href="#how-it-works"
          style={{
            background: "#ffffff",
            color: "#0f172a",
            border: "1px solid #cbd5e1",
            padding: "14px 22px",
            borderRadius: "6px",
            fontSize: "15px",
            fontWeight: 600,
            textDecoration: "none",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}
          className="btn-tactile"
        >
          <Play size={15} color="#2563eb" /> See Broker Illustration
        </a>
      </div>

      <div style={{ fontSize: "12px", color: "#64748b" }}>
        Self-hosted · Operator-configured monthly allowance
      </div>

      {/* Architecture Metrics Grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))",
          gap: "14px",
          marginTop: "54px",
          textAlign: "left",
        }}
      >
        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "20px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
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
            Credential delivery
          </div>
          <div
            style={{
              fontSize: "28px",
              fontWeight: 800,
              fontFamily: "monospace",
              color: "#059669",
              margin: "4px 0",
            }}
          >
            Brokered
          </div>
          <div style={{ fontSize: "11px", color: "#64748b" }}>
            Isolated V8 edge memory injection
          </div>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "20px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
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
            Request execution
          </div>
          <div
            style={{
              fontSize: "28px",
              fontWeight: 800,
              fontFamily: "monospace",
              color: "#2563eb",
              margin: "4px 0",
            }}
          >
            Bounded IO
          </div>
          <div style={{ fontSize: "11px", color: "#64748b" }}>
            Global edge worker distribution
          </div>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "20px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
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
            Firewall Protection
          </div>
          <div
            style={{
              fontSize: "28px",
              fontWeight: 800,
              fontFamily: "monospace",
              color: "#4f46e5",
              margin: "4px 0",
            }}
          >
            Allowlisted
          </div>
          <div style={{ fontSize: "11px", color: "#64748b" }}>
            HTTPS domain, method, and path policies
          </div>
        </div>

        <div
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            padding: "20px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
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
              fontSize: "28px",
              fontWeight: 800,
              fontFamily: "monospace",
              color: "#0f172a",
              margin: "4px 0",
            }}
          >
            SQLite DO
          </div>
          <div style={{ fontSize: "11px", color: "#64748b" }}>
            Bitwarden / 1Password service account
          </div>
        </div>
      </div>
    </section>
  );
}
