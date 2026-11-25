import { AlertTriangle, X } from "lucide-react";
import { SignInModal } from "./landing/SignInModal";
import { OnboardingForm } from "./dashboard/OnboardingForm";
import { LandingPage } from "./landing/LandingPage";
import { Sidebar } from "./dashboard/Sidebar";
import { TopBar } from "./dashboard/TopBar";
import { AuthGate } from "./dashboard/AuthGate";
import { OverviewTab } from "./dashboard/tabs/OverviewTab";
import { SecretsTab } from "./dashboard/tabs/SecretsTab";
import { VaultsTab } from "./dashboard/tabs/VaultsTab";
import { PoliciesTab } from "./dashboard/tabs/PoliciesTab";
import { SimulatorTab } from "./dashboard/tabs/SimulatorTab";
import { CompanionTab } from "./dashboard/tabs/CompanionTab";
import { AuditTab } from "./dashboard/tabs/AuditTab";
import { IntegrationsTab } from "./dashboard/tabs/IntegrationsTab";
import { useAppController } from "./app/useAppController";

export default function App() {
  const c = useAppController();
  const {
    view,
    activeTab,
    user,
    isLoadingUser,
    showAuthModal,
    dashboardNotice,
    setDashboardNotice,
    sidebarOpen,
    setSidebarOpen,
  } = c;

  const notice = dashboardNotice && (
    <div role="alert" className="notice notice-error" style={{ margin: 0 }}>
      <AlertTriangle size={16} />
      <div className="notice-body">{dashboardNotice}</div>
      <button
        type="button"
        className="btn btn-ghost btn-icon btn-sm"
        aria-label="Dismiss notice"
        onClick={() => setDashboardNotice(null)}
      >
        <X size={14} />
      </button>
    </div>
  );

  return (
    <div className="app-root">
      {showAuthModal && <SignInModal c={c} />}

      <p className="status-banner">
        Strict broker profile: Bitwarden and 1Password service accounts, with
        owner-approved local companions for password-manager stores. Agent
        credentials require DPoP. Billing is disabled.
        {user && <span> Account: {user.id}. </span>}
      </p>

      {view === "landing" && (
        <>
          {notice && (
            <div className="container" style={{ paddingTop: 16 }}>
              {notice}
            </div>
          )}
          <LandingPage c={c} />
        </>
      )}

      {view === "dashboard" && !user && (
        <AuthGate c={c} loading={isLoadingUser} />
      )}

      {view === "dashboard" && user && (
        <div className="app-shell">
          <Sidebar c={c} />
          <button
            type="button"
            className="sidebar-scrim"
            data-open={sidebarOpen}
            aria-label="Close navigation"
            tabIndex={sidebarOpen ? 0 : -1}
            onClick={() => setSidebarOpen(false)}
          />
          <main className="app-main">
            <TopBar c={c} />
            <div className="app-content">
              {notice}
              {user.onboarding && !user.onboarding.complete && (
                <OnboardingForm c={c} />
              )}
              {activeTab === "overview" && <OverviewTab c={c} />}
              {activeTab === "secrets" && <SecretsTab c={c} />}
              {activeTab === "vaults" && <VaultsTab c={c} />}
              {activeTab === "policies" && <PoliciesTab c={c} />}
              {activeTab === "simulator" && <SimulatorTab c={c} />}
              {activeTab === "oauth" && <CompanionTab />}
              {activeTab === "audit" && <AuditTab c={c} />}
              {activeTab === "integrations" && <IntegrationsTab c={c} />}
            </div>
          </main>
        </div>
      )}
    </div>
  );
}
