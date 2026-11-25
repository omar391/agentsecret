import type { AppController } from "../app/useAppController";
import { Shield } from "lucide-react";

export function LandingHeader({ c }: { c: AppController }) {
  const { setShowAuthModal, setView, user } = c;
  return (
    <header
      style={{
        borderBottom: "1px solid #eaecf0",
        background: "rgba(255, 255, 255, 0.95)",
        backdropFilter: "blur(8px)",
        position: "sticky",
        top: 0,
        zIndex: 40,
      }}
    >
      <div
        style={{
          maxWidth: "1160px",
          margin: "0 auto",
          padding: "16px 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        {/* Brand Logo */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            cursor: "pointer",
          }}
          onClick={() => setView("landing")}
        >
          <div
            style={{
              background: "#0f172a",
              color: "#ffffff",
              padding: "7px",
              borderRadius: "7px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Shield size={18} strokeWidth={2.4} />
          </div>
          <span
            style={{
              fontSize: "16px",
              fontWeight: 800,
              letterSpacing: "-0.03em",
              color: "#0f172a",
            }}
          >
            AgentSecret
          </span>
        </div>

        {/* Subdued Funnel Anchor Links */}
        <nav style={{ display: "flex", alignItems: "center", gap: "28px" }}>
          <a
            href="#how-it-works"
            style={{
              fontSize: "13px",
              color: "#64748b",
              textDecoration: "none",
              fontWeight: 500,
            }}
          >
            How It Works
          </a>
          <a
            href="#how-it-works"
            style={{
              fontSize: "13px",
              color: "#64748b",
              textDecoration: "none",
              fontWeight: 500,
            }}
          >
            Broker Illustration
          </a>
          <a
            href="#integrations"
            style={{
              fontSize: "13px",
              color: "#64748b",
              textDecoration: "none",
              fontWeight: 500,
            }}
          >
            Integrations
          </a>
          <a
            href="#pricing"
            style={{
              fontSize: "13px",
              color: "#64748b",
              textDecoration: "none",
              fontWeight: 500,
            }}
          >
            Pricing
          </a>
        </nav>

        {/* Primary Conversion Actions */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <button
            onClick={() => setShowAuthModal(true)}
            style={{
              background: "transparent",
              border: "none",
              color: "#0f172a",
              fontSize: "13px",
              fontWeight: 600,
              cursor: "pointer",
              padding: "6px 12px",
            }}
          >
            Sign in
          </button>
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
              padding: "8px 16px",
              borderRadius: "6px",
              fontSize: "13px",
              fontWeight: 600,
              cursor: "pointer",
            }}
            className="btn-tactile"
          >
            Get Started Free
          </button>
        </div>
      </div>
    </header>
  );
}
