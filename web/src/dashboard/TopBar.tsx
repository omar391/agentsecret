import type { AppController } from "../app/useAppController";
import { ChevronRight, Zap } from "lucide-react";

export function TopBar({ c }: { c: AppController }) {
  const { activeTab, setActiveTab, user } = c;
  return (
    <div
      style={{
        background: "#ffffff",
        borderBottom: "1px solid #eaecf0",
        padding: "14px 28px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          fontSize: "13px",
        }}
      >
        <span style={{ color: "#64748b" }}>Workspace</span>
        <ChevronRight size={14} color="#94a3b8" />
        <span
          style={{
            fontWeight: 700,
            color: "#0f172a",
            textTransform: "capitalize",
          }}
        >
          {activeTab.replace(/([A-Z])/g, " $1")}
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            fontSize: "11px",
            color: "#059669",
            background: "#ecfdf5",
            padding: "4px 10px",
            borderRadius: "4px",
            border: "1px solid #a7f3d0",
            fontWeight: 600,
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
          {user ? "Account session" : "Not signed in"}
        </div>

        <button
          onClick={() => setActiveTab("overview")}
          style={{
            background: "#0f172a",
            color: "#ffffff",
            border: "none",
            padding: "6px 12px",
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
          <Zap size={13} fill="#ffffff" /> Allowance
        </button>
      </div>
    </div>
  );
}
