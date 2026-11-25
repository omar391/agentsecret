import { Shield } from "lucide-react";
import type { AppController } from "../app/useAppController";

/** Signed-out (or still loading) dashboard: no data, no stand-in identity. */
export function AuthGate({
  c,
  loading,
}: {
  c: AppController;
  loading: boolean;
}) {
  const { setView, setShowAuthModal } = c;
  return (
    <main className="landing-grid" style={{ minHeight: "calc(100vh - 34px)" }}>
      <div
        className="container"
        style={{ display: "grid", placeItems: "center", padding: "64px 16px" }}
      >
        <div className="card stack" style={{ width: "min(440px, 100%)" }}>
          <span className="brand">
            <span className="brand-mark">
              <Shield size={16} />
            </span>
            AgentSecret
          </span>
          {loading ? (
            <div className="stack-sm" aria-busy="true" aria-live="polite">
              <span className="sr-only">Checking your session…</span>
              <div className="skeleton" style={{ width: "60%" }} />
              <div className="skeleton" style={{ width: "90%" }} />
              <div className="skeleton" style={{ width: "75%" }} />
            </div>
          ) : (
            <>
              <div className="stack-sm">
                <span className="badge">
                  <span className="dot" /> Not signed in
                </span>
                <h1 className="h2">Sign in to your dashboard</h1>
                <p className="muted">
                  Vault connections, policies, approvals and audit records are
                  only shown to the signed-in account that owns them.
                </p>
              </div>
              <p className="subtle">
                Broker:{" "}
                <code className="code-inline">{window.location.origin}</code>
              </p>
              <div className="form-actions">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => setShowAuthModal(true)}
                >
                  Sign in
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setView("landing")}
                >
                  ← Back to Public Site
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
