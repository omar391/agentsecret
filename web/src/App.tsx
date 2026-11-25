import { CheckCircle } from "lucide-react";
import { SignInModal } from "./landing/SignInModal";
import { OnboardingForm } from "./dashboard/OnboardingForm";
import { LandingPage } from "./landing/LandingPage";
import { Sidebar } from "./dashboard/Sidebar";
import { TopBar } from "./dashboard/TopBar";
import { OverviewTab } from "./dashboard/tabs/OverviewTab";
import { SecretsTab } from "./dashboard/tabs/SecretsTab";
import { VaultsTab } from "./dashboard/tabs/VaultsTab";
import { SimulatorTab } from "./dashboard/tabs/SimulatorTab";
import { CompanionTab } from "./dashboard/tabs/CompanionTab";
import { AuditTab } from "./dashboard/tabs/AuditTab";
import { IntegrationsTab } from "./dashboard/tabs/IntegrationsTab";
import { useAppController } from "./app/useAppController";
import { PoliciesTab } from "./dashboard/tabs/PoliciesTab";

export default function App() {
  const c = useAppController();
  const {
    view,
    setView,
    activeTab,
    user,
    setUser,
    showAuthModal,
    clearVaultCredentialDraft,
    dashboardNotice,
    setDashboardNotice,
  } = c;

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#ffffff",
        color: "#0f172a",
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif',
      }}
    >
      {/* ─────────────────────────────────────────────────────────────
          SOCIAL LOGIN MODAL
         ───────────────────────────────────────────────────────────── */}
      {showAuthModal && <SignInModal c={c} />}

      <div
        style={{
          padding: "10px 24px",
          fontSize: 12,
          background: "#f1f5f9",
          color: "#334155",
        }}
      >
        Strict broker profile: Bitwarden and 1Password service accounts, with
        owner-approved local companions for password-manager stores. Agent
        credentials require DPoP. Billing is disabled.
        {user && <span> Account: {user.id}. </span>}
      </div>

      {view === "dashboard" &&
        user &&
        user.onboarding &&
        !user.onboarding.complete && <OnboardingForm c={c} />}

      {/* ─────────────────────────────────────────────────────────────
          MODE 1: SALES FUNNEL PUBLIC LANDING PAGE
         ───────────────────────────────────────────────────────────── */}
      {view === "landing" && <LandingPage c={c} />}

      {/* ─────────────────────────────────────────────────────────────
          MODE 2: AUTHENTICATED OPERATOR DASHBOARD
          (Left-Sided Dashboard Menus - Dribbble SaaS Standard)
         ───────────────────────────────────────────────────────────── */}
      {view === "dashboard" && (
        <div
          style={{ display: "flex", minHeight: "100vh", background: "#f8fafc" }}
        >
          {/* ─────────────────────────────────────────────────────────
              LEFT-SIDED DASHBOARD SIDEBAR (Dribbble Standard)
             ───────────────────────────────────────────────────────── */}
          <Sidebar c={c} />

          {/* ─────────────────────────────────────────────────────────
              MAIN DASHBOARD CONTENT AREA
             ───────────────────────────────────────────────────────── */}
          <main
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              minWidth: 0,
              height: "100vh",
              overflowY: "auto",
            }}
          >
            {/* Top Workspace Header & Breadcrumbs */}
            <TopBar c={c} />

            {/* Notification Banner if present */}
            {dashboardNotice && (
              <div
                role="alert"
                style={{
                  background: "#fff1f2",
                  borderBottom: "1px solid #fecdd3",
                  color: "#9f1239",
                  padding: "10px 28px",
                  fontSize: "12px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "8px" }}
                >
                  <CheckCircle size={15} /> {dashboardNotice}
                </div>
                <button
                  onClick={() => setDashboardNotice(null)}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#9f1239",
                    cursor: "pointer",
                    fontWeight: 700,
                  }}
                >
                  ×
                </button>
              </div>
            )}

            {/* Content Container */}
            <div
              style={{
                padding: "28px",
                maxWidth: "1000px",
                display: "flex",
                flexDirection: "column",
                gap: "20px",
              }}
            >
              <button
                onClick={async () => {
                  try {
                    const res = await fetch("/api/user/revoke", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: "{}",
                    });
                    if (!res.ok) throw new Error();
                    setUser(null);
                    clearVaultCredentialDraft();
                    setView("landing");
                    setDashboardNotice(
                      "Tenant sessions and outstanding grants revoked. Sign in again.",
                    );
                  } catch {
                    setDashboardNotice(
                      "Revocation failed. Retry from an authenticated customer session.",
                    );
                  }
                }}
              >
                Revoke all tenant sessions and pending grants
              </button>
              {/* TAB: OVERVIEW */}
              {activeTab === "overview" && <OverviewTab c={c} />}

              {/* TAB: SAVE SECRET */}
              {activeTab === "secrets" && <SecretsTab c={c} />}

              {/* TAB: VAULT CONNECTIONS */}
              {activeTab === "vaults" && <VaultsTab c={c} />}

              {/* TAB: SECRET POLICIES */}
              {activeTab === "policies" && <PoliciesTab c={c} />}

              {/* TAB: EGRESS SIMULATOR */}
              {activeTab === "simulator" && <SimulatorTab c={c} />}

              {activeTab === "oauth" && <CompanionTab c={c} />}

              {/* TAB: AUDIT TRAIL */}
              {activeTab === "audit" && <AuditTab c={c} />}

              {/* TAB: AGENT INTEGRATIONS */}
              {activeTab === "integrations" && <IntegrationsTab c={c} />}
            </div>
          </main>
        </div>
      )}
    </div>
  );
}
