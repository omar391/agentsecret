import type { AppController } from "../app/useAppController";
import { ChevronRight, Gauge, Menu } from "lucide-react";
import { tabLabel } from "./Sidebar";

export function TopBar({ c }: { c: AppController }) {
  const { activeTab, setActiveTab, setSidebarOpen, user } = c;
  const used = user?.quotaUsed ?? 0;
  const limit = user?.quotaLimit ?? 0;
  return (
    <header className="topbar">
      <div className="row" style={{ gap: 8, minWidth: 0 }}>
        <button
          type="button"
          className="btn btn-ghost btn-icon sidebar-toggle"
          aria-label="Open navigation"
          onClick={() => setSidebarOpen(true)}
        >
          <Menu size={18} />
        </button>
        <nav aria-label="Breadcrumb" className="row small" style={{ gap: 6 }}>
          <span className="muted hide-mobile">Workspace</span>
          <ChevronRight size={14} className="hide-mobile" aria-hidden="true" />
          <span style={{ fontWeight: 700 }} aria-current="page">
            {tabLabel(activeTab)}
          </span>
        </nav>
      </div>

      <div className="row" style={{ gap: 8 }}>
        <span className="badge badge-success hide-mobile">
          <span className="dot dot-success" />
          {user ? "Account session" : "Not signed in"}
        </span>
        {user && limit > 0 && (
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setActiveTab("overview")}
            title="Monthly allowance — open Overview"
          >
            <Gauge size={14} />
            {used.toLocaleString()} / {limit.toLocaleString()} this month
          </button>
        )}
      </div>
    </header>
  );
}
