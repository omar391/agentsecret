import type { AppController } from "../app/useAppController";

export function LandingFooter({ c }: { c: AppController }) {
  const { setActiveTab, setView } = c;
  return (
    <footer
      style={{
        borderTop: "1px solid #eaecf0",
        padding: "32px 24px",
        textAlign: "center",
        fontSize: "12px",
        color: "#64748b",
        background: "#ffffff",
        marginTop: "auto",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          gap: "20px",
          marginBottom: "12px",
        }}
      >
        <span
          style={{ cursor: "pointer", color: "#0f172a" }}
          onClick={() => setView("landing")}
        >
          Home
        </span>
        <span
          style={{ cursor: "pointer", color: "#0f172a" }}
          onClick={() => {
            setView("dashboard");
            setActiveTab("oauth");
          }}
        >
          Companion authorization
        </span>
        <a
          href="/.well-known/oauth-protected-resource"
          target="_blank"
          rel="noreferrer"
          style={{ color: "#64748b", textDecoration: "none" }}
        >
          Broker metadata
        </a>
        <a
          href="/privacy.html"
          style={{ color: "#64748b", textDecoration: "none" }}
        >
          Privacy
        </a>
        <a
          href="/source.tar.gz"
          download
          style={{ color: "#64748b", textDecoration: "none" }}
        >
          Corresponding Source
        </a>
        <a
          href="/source-revision.json"
          target="_blank"
          rel="noreferrer"
          style={{ color: "#64748b", textDecoration: "none" }}
        >
          Source revision
        </a>
        <a
          href="https://agentsecret.astronlab.com/health"
          target="_blank"
          rel="noreferrer"
          style={{ color: "#64748b", textDecoration: "none" }}
        >
          Health Check
        </a>
      </div>
      <div>AgentSecret by AstronLab · Policy-bound broker access</div>
    </footer>
  );
}
