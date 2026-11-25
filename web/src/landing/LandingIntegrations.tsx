import type { AppController } from "../app/useAppController";
import { Check, Copy } from "lucide-react";

export function LandingIntegrations({ c }: { c: AppController }) {
  const { copiedSnippet, copyToClipboard } = c;
  const origin = window.location.origin;
  const cli = `agentsecret login --server ${origin} --aliases API_TOKEN
agentsecret request --alias API_TOKEN --url https://api.example.com/status`;
  const mcp = JSON.stringify(
    {
      mcpServers: {
        agentsecret: {
          command: "agentsecret",
          args: ["mcp", "--server", origin],
        },
      },
    },
    null,
    2,
  );
  return (
    <section id="integrations" className="section">
      <div className="container">
        <div className="section-head">
          <span className="eyebrow">Integrations</span>
          <h2 className="h1">Connect your agent</h2>
          <p className="muted">
            Authenticate the companion once, then use a local stdio MCP
            configuration. The companion signs each cloud request with its own
            device key.
          </p>
        </div>
        <div className="grid-2">
          <div className="card stack-sm">
            <span className="eyebrow">1 · Companion login</span>
            <pre className="code-block">{cli}</pre>
          </div>
          <div className="card stack-sm">
            <div className="row-between">
              <span className="eyebrow">2 · MCP configuration</span>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => copyToClipboard(mcp, "landing-mcp")}
              >
                {copiedSnippet === "landing-mcp" ? (
                  <Check size={14} />
                ) : (
                  <Copy size={14} />
                )}
                {copiedSnippet === "landing-mcp"
                  ? "Copied"
                  : "Copy MCP configuration"}
              </button>
            </div>
            <pre className="code-block">{mcp}</pre>
          </div>
        </div>
        <p className="subtle" style={{ marginTop: 16, textAlign: "center" }}>
          Direct remote MCP clients must support PKCE, DPoP, and a registered
          callback. Host support must be verified. OpenAPI Actions and legacy
          SSE are unavailable in this profile.
        </p>
      </div>
    </section>
  );
}
