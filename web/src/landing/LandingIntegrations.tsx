import type { AppController } from "../app/useAppController";

export function LandingIntegrations({ c }: { c: AppController }) {
  const { copiedSnippet, copyToClipboard } = c;
  return (
    <section
      id="integrations"
      style={{
        maxWidth: "1080px",
        margin: "40px auto",
        padding: "24px",
        width: "100%",
        border: "1px solid #e2e8f0",
        borderRadius: "8px",
      }}
    >
      <h2>Connect your agent</h2>
      <p>
        Authenticate the companion once, then use a local stdio MCP
        configuration. The companion signs each cloud request with its own
        device key.
      </p>
      <pre
        style={{ overflowX: "auto" }}
      >{`agentsecret login --server ${window.location.origin} --aliases API_TOKEN
    agentsecret request --alias API_TOKEN --url https://api.example.com/status`}</pre>
      <pre style={{ overflowX: "auto" }}>
        {JSON.stringify(
          {
            mcpServers: {
              agentsecret: {
                command: "agentsecret",
                args: ["mcp", "--server", window.location.origin],
              },
            },
          },
          null,
          2,
        )}
      </pre>
      <button
        onClick={() =>
          copyToClipboard(
            JSON.stringify(
              {
                mcpServers: {
                  agentsecret: {
                    command: "agentsecret",
                    args: ["mcp", "--server", window.location.origin],
                  },
                },
              },
              null,
              2,
            ),
            "landing-mcp",
          )
        }
      >
        {copiedSnippet === "landing-mcp" ? "Copied" : "Copy MCP configuration"}
      </button>
      <p>
        Direct remote MCP clients must support PKCE, DPoP, and a registered
        callback. Host support must be verified. OpenAPI Actions and legacy SSE
        are unavailable in this profile.
      </p>
    </section>
  );
}
