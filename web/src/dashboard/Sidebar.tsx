import type { AppController } from "../app/useAppController";
import { DashboardTab } from "../app/types";
import {
  Code2,
  Database,
  Globe,
  Key,
  Layers,
  List,
  LogOut,
  Play,
  Shield,
} from "lucide-react";

export function Sidebar({ c }: { c: AppController }) {
  const { activeTab, handleLogout, setActiveTab, setView, user } = c;
  return (
    <aside
      style={{
        width: "250px",
        background: "#ffffff",
        borderRight: "1px solid #eaecf0",
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        position: "sticky",
        top: 0,
        height: "100vh",
      }}
    >
      {/* Sidebar Header & Brand */}
      <div
        style={{
          padding: "18px 20px",
          borderBottom: "1px solid #f1f5f9",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "9px",
            cursor: "pointer",
          }}
          onClick={() => setView("landing")}
        >
          <div
            style={{
              background: "#0f172a",
              color: "#ffffff",
              padding: "6px",
              borderRadius: "6px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Shield size={16} strokeWidth={2.4} />
          </div>
          <div>
            <div
              style={{
                fontSize: "14px",
                fontWeight: 800,
                letterSpacing: "-0.02em",
                color: "#0f172a",
              }}
            >
              AgentSecret
            </div>
            <div
              style={{
                fontSize: "10px",
                color: "#64748b",
                textTransform: "uppercase",
                letterSpacing: "0.04em",
                fontFamily: "monospace",
              }}
            >
              {window.location.origin}
            </div>
          </div>
        </div>
      </div>

      <div
        style={{
          display: "flex",
          gap: 12,
          padding: "10px 20px",
          fontSize: 12,
        }}
      >
        <a href="/source.tar.gz" download>
          Corresponding Source
        </a>
        <a href="/source-revision.json" target="_blank" rel="noreferrer">
          Source revision
        </a>
      </div>

      {/* Workspace Selector Pill */}
      <div style={{ padding: "12px 16px" }}>
        <div
          style={{
            background: "#f1f5f9",
            borderRadius: "6px",
            padding: "8px 12px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <div
              style={{
                width: "7px",
                height: "7px",
                borderRadius: "50%",
                background: "#059669",
              }}
            />
            <span
              style={{
                fontSize: "12px",
                fontWeight: 700,
                color: "#0f172a",
              }}
            >
              {user?.id || "Not signed in"}
            </span>
          </div>
          <span
            style={{
              fontSize: "10px",
              background: "#ffffff",
              border: "1px solid #cbd5e1",
              padding: "1px 5px",
              borderRadius: "3px",
              fontWeight: 600,
              color: "#475569",
            }}
          >
            {user?.plan?.toUpperCase() || "UNAUTHENTICATED"}
          </span>
        </div>
      </div>

      {/* Navigation Menus */}
      <div
        style={{
          padding: "6px 12px",
          flex: 1,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: "3px",
        }}
      >
        <div
          style={{
            fontSize: "10px",
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            color: "#94a3b8",
            padding: "6px 10px",
          }}
        >
          Workspace
        </div>

        {[
          {
            id: "overview",
            label: "Overview",
            icon: <Layers size={15} />,
          },
          {
            id: "vaults",
            label: "Vault Connections",
            icon: <Database size={15} />,
          },
          {
            id: "secrets",
            label: "Secrets",
            icon: <Key size={15} />,
          },
          {
            id: "policies",
            label: "Secret Policies",
            icon: <Globe size={15} />,
          },
          {
            id: "simulator",
            label: "Egress Simulator",
            icon: <Play size={15} />,
          },
        ].map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id as DashboardTab)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              width: "100%",
              padding: "8px 12px",
              borderRadius: "6px",
              fontSize: "12.5px",
              fontWeight: activeTab === item.id ? 700 : 500,
              color: activeTab === item.id ? "#0f172a" : "#475569",
              background: activeTab === item.id ? "#f1f5f9" : "transparent",
              border: "none",
              cursor: "pointer",
              textAlign: "left",
            }}
            className="btn-tactile"
          >
            <span
              style={{
                color: activeTab === item.id ? "#0f172a" : "#64748b",
              }}
            >
              {item.icon}
            </span>
            {item.label}
          </button>
        ))}

        <div
          style={{
            fontSize: "10px",
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            color: "#94a3b8",
            padding: "12px 10px 6px 10px",
          }}
        >
          Security &amp; Agents
        </div>

        {[
          {
            id: "oauth",
            label: "Companion authorization",
            icon: <Key size={15} />,
          },
          { id: "audit", label: "Audit Trail", icon: <List size={15} /> },
          {
            id: "integrations",
            label: "Agent Setup",
            icon: <Code2 size={15} />,
          },
        ].map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id as DashboardTab)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              width: "100%",
              padding: "8px 12px",
              borderRadius: "6px",
              fontSize: "12.5px",
              fontWeight: activeTab === item.id ? 700 : 500,
              color: activeTab === item.id ? "#0f172a" : "#475569",
              background: activeTab === item.id ? "#f1f5f9" : "transparent",
              border: "none",
              cursor: "pointer",
              textAlign: "left",
            }}
            className="btn-tactile"
          >
            <span
              style={{
                color: activeTab === item.id ? "#0f172a" : "#64748b",
              }}
            >
              {item.icon}
            </span>
            {item.label}
          </button>
        ))}
      </div>

      {/* Sidebar Bottom: User Profile & Public Site Link */}
      <div
        style={{
          padding: "14px 16px",
          borderTop: "1px solid #eaecf0",
          background: "#fafbfc",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "10px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
            <img
              src={
                user?.avatarUrl ||
                "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80"
              }
              alt="User"
              style={{
                width: "28px",
                height: "28px",
                borderRadius: "50%",
                objectFit: "cover",
              }}
            />
            <div>
              <div
                style={{
                  fontSize: "12px",
                  fontWeight: 700,
                  color: "#0f172a",
                  lineHeight: 1.2,
                }}
              >
                {user?.name || "Developer"}
              </div>
              <div style={{ fontSize: "10px", color: "#64748b" }}>
                {user?.email || "dev@astronlab.com"}
              </div>
            </div>
          </div>

          <button
            onClick={handleLogout}
            title="Sign Out"
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              cursor: "pointer",
              padding: "4px",
            }}
          >
            <LogOut size={14} />
          </button>
        </div>

        <button
          onClick={() => setView("landing")}
          style={{
            width: "100%",
            background: "#ffffff",
            border: "1px solid #d1d5db",
            color: "#475569",
            padding: "6px 10px",
            borderRadius: "5px",
            fontSize: "11px",
            fontWeight: 600,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "6px",
          }}
          className="btn-tactile"
        >
          ← Back to Public Site
        </button>
      </div>
    </aside>
  );
}
