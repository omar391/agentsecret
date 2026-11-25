import type { AppController } from "../app/useAppController";
import { Shield } from "lucide-react";

export function LandingFooter({ c }: { c: AppController }) {
  const { setActiveTab, setView } = c;
  return (
    <footer className="site-footer">
      <div className="container stack">
        <div className="row-between">
          <span className="brand" style={{ fontSize: 14 }}>
            <span className="brand-mark" style={{ width: 24, height: 24 }}>
              <Shield size={13} strokeWidth={2.4} />
            </span>
            AgentSecret
          </span>
          <nav className="footer-links" aria-label="Footer">
            <button type="button" onClick={() => setView("landing")}>
              Home
            </button>
            <button
              type="button"
              onClick={() => {
                setView("dashboard");
                setActiveTab("oauth");
              }}
            >
              Companion authorization
            </button>
            <a
              href="/.well-known/oauth-protected-resource"
              target="_blank"
              rel="noreferrer"
            >
              Broker metadata
            </a>
            <a href="/privacy.html">Privacy</a>
            <a href="/source.tar.gz" download>
              Corresponding Source
            </a>
            <a href="/source-revision.json" target="_blank" rel="noreferrer">
              Source revision
            </a>
            <a href="/health" target="_blank" rel="noreferrer">
              Health Check
            </a>
          </nav>
        </div>
        <div>AgentSecret by AstronLab · Policy-bound broker access</div>
      </div>
    </footer>
  );
}
