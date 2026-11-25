import type { AppController } from "../../app/useAppController";
import { Check, Copy } from "lucide-react";
import { PageHeader } from "../PageHeader";

export function IntegrationsTab({ c }: { c: AppController }) {
  const { copiedSnippet, copyToClipboard, user } = c;
  const tenant = user ? ` --tenant ${user.id}` : "";
  const origin = window.location.origin;
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
    <>
      <PageHeader
        title="Agent Setup"
        description="Authorize the companion CLI with the aliases this agent may use. The cloud broker supplies the tools; the companion signs requests locally."
      />
      <section className="card stack">
        <div className="stack-sm">
          <span className="eyebrow">
            1 · Companion login and a test request
          </span>
          <pre className="code-block">{`agentsecret login --server ${origin}${tenant} --aliases YOUR_ALIAS
agentsecret request --alias YOUR_ALIAS --url https://your-allowed-api.example/path`}</pre>
        </div>
        <div className="stack-sm">
          <div className="row-between">
            <span className="eyebrow">2 · stdio MCP configuration</span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => copyToClipboard(mcp, "claude")}
            >
              {copiedSnippet === "claude" ? (
                <Check size={14} />
              ) : (
                <Copy size={14} />
              )}
              {copiedSnippet === "claude"
                ? "Copied"
                : "Copy stdio MCP configuration"}
            </button>
          </div>
          <pre className="code-block">{mcp}</pre>
        </div>
        <p className="subtle">
          The remote endpoint is{" "}
          <code className="code-inline">{origin}/mcp</code>. Direct remote
          clients must support PKCE and DPoP, with a registered callback. A host
          plugin&apos;s private OAuth store is not shared with this CLI.
        </p>
      </section>
    </>
  );
}
