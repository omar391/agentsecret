import type { AppController } from "../../app/useAppController";

export function IntegrationsTab({ c }: { c: AppController }) {
  const { copiedSnippet, copyToClipboard } = c;
  return (
    <section
      style={{
        background: "#fff",
        border: "1px solid #e2e8f0",
        borderRadius: 8,
        padding: 24,
      }}
    >
      <h3>Connect an agent</h3>
      <p>
        Authorize the companion CLI with the aliases this agent may use. The
        cloud broker supplies the tools; the companion signs requests locally.
      </p>
      <pre
        style={{ whiteSpace: "pre-wrap" }}
      >{`agentsecret login --server ${window.location.origin} --aliases YOUR_ALIAS
    agentsecret request --alias YOUR_ALIAS --url https://your-allowed-api.example/path`}</pre>
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
            "claude",
          )
        }
      >
        {copiedSnippet === "claude" ? "Copied" : "Copy stdio MCP configuration"}
      </button>
      <pre style={{ whiteSpace: "pre-wrap" }}>
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
      <p>
        The remote endpoint is <code>{window.location.origin}/mcp</code>. Direct
        remote clients must support PKCE and DPoP, with a registered callback. A
        host plugin's private OAuth store is not shared with this CLI.
      </p>
    </section>
  );
}
