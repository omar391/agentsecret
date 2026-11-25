import { useState, type ReactNode } from "react";
import type { AppController } from "../app/useAppController";
import type { DashboardTab } from "../app/types";
import { ConfirmDialog } from "../ui/ConfirmDialog";
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
  ShieldOff,
} from "lucide-react";

export const NAV_GROUPS: {
  title: string;
  items: { id: DashboardTab; label: string; icon: ReactNode }[];
}[] = [
  {
    title: "Workspace",
    items: [
      { id: "overview", label: "Overview", icon: <Layers size={16} /> },
      {
        id: "vaults",
        label: "Vault Connections",
        icon: <Database size={16} />,
      },
      { id: "secrets", label: "Secrets", icon: <Key size={16} /> },
      { id: "policies", label: "Secret Policies", icon: <Globe size={16} /> },
      { id: "simulator", label: "Egress Simulator", icon: <Play size={16} /> },
    ],
  },
  {
    title: "Security & Agents",
    items: [
      {
        id: "oauth",
        label: "Companion authorization",
        icon: <Key size={16} />,
      },
      { id: "audit", label: "Audit Trail", icon: <List size={16} /> },
      { id: "integrations", label: "Agent Setup", icon: <Code2 size={16} /> },
    ],
  },
];

export function tabLabel(tab: DashboardTab): string {
  for (const group of NAV_GROUPS)
    for (const item of group.items) if (item.id === tab) return item.label;
  return tab;
}

function initials(name: string | undefined, fallback: string): string {
  const source = (name || fallback || "?").trim();
  const parts = source.split(/\s+/).filter(Boolean);
  const letters =
    parts.length > 1
      ? parts[0][0] + parts[parts.length - 1][0]
      : source.slice(0, 2);
  return letters.toUpperCase();
}

export function Sidebar({ c }: { c: AppController }) {
  const {
    activeTab,
    handleLogout,
    handleRevokeAllSessions,
    setActiveTab,
    setView,
    sidebarOpen,
    user,
  } = c;
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  return (
    <>
      <aside
        className="sidebar"
        data-open={sidebarOpen}
        aria-label="Dashboard navigation"
      >
        <div className="stack-sm">
          <button
            type="button"
            className="brand"
            onClick={() => setView("landing")}
            aria-label="AgentSecret public site"
          >
            <span className="brand-mark">
              <Shield size={16} strokeWidth={2.4} />
            </span>
            AgentSecret
          </button>
          <span className="tiny muted break mono">
            {window.location.origin}
          </span>
        </div>

        <div className="card-flat stack-sm" style={{ padding: "10px 12px" }}>
          <div className="row-between">
            <span className="row" style={{ gap: 8, minWidth: 0 }}>
              <span className={"dot " + (user ? "dot-success" : "")} />
              <span className="small break" style={{ fontWeight: 600 }}>
                {user?.id || "Not signed in"}
              </span>
            </span>
            <span className="badge">
              {user?.plan?.toUpperCase() || "UNAUTHENTICATED"}
            </span>
          </div>
        </div>

        <nav className="stack">
          {NAV_GROUPS.map((group) => (
            <div key={group.title} className="sidebar-section">
              <span className="eyebrow">{group.title}</span>
              {group.items.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="nav-item"
                  aria-current={activeTab === item.id ? "page" : undefined}
                  onClick={() => setActiveTab(item.id)}
                >
                  {item.icon}
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="row tiny">
            <a className="link-btn" href="/source.tar.gz" download>
              Corresponding Source
            </a>
            <a
              className="link-btn"
              href="/source-revision.json"
              target="_blank"
              rel="noreferrer"
            >
              Source revision
            </a>
          </div>
          {user && (
            <div className="user-card">
              <span className="avatar" aria-hidden="true">
                {initials(user.name, user.id)}
              </span>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="small truncate" style={{ fontWeight: 650 }}>
                  {user.name || user.id}
                </div>
                {user.email && (
                  <div className="tiny muted truncate">{user.email}</div>
                )}
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-icon btn-sm"
                aria-label="Sign out"
                title="Sign out"
                onClick={handleLogout}
              >
                <LogOut size={15} />
              </button>
            </div>
          )}
          {user && (
            <button
              type="button"
              className="btn btn-danger btn-sm btn-block"
              onClick={() => setConfirmRevoke(true)}
            >
              <ShieldOff size={14} />
              Revoke all sessions
            </button>
          )}
          <button
            type="button"
            className="btn btn-secondary btn-sm btn-block"
            onClick={() => setView("landing")}
          >
            ← Back to Public Site
          </button>
        </div>
      </aside>
      {confirmRevoke && (
        <ConfirmDialog
          title="Revoke all sessions?"
          body="This signs out every browser and companion session for this account and cancels outstanding grants. You will need to sign in again."
          confirmLabel="Revoke all sessions"
          onCancel={() => setConfirmRevoke(false)}
          onConfirm={handleRevokeAllSessions}
        />
      )}
    </>
  );
}
