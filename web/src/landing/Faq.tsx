import type { AppController } from "../app/useAppController";

export function Faq({ c }: { c: AppController }) {
  const { openFaq, setOpenFaq } = c;
  return (
    <section
      style={{
        maxWidth: "820px",
        margin: "40px auto 70px auto",
        padding: "0 24px",
        width: "100%",
      }}
    >
      <h3
        style={{
          fontSize: "24px",
          fontWeight: 800,
          textAlign: "center",
          marginBottom: "24px",
          color: "#0f172a",
        }}
      >
        Frequently Asked Questions
      </h3>

      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
        {[
          {
            q: "Does AgentSecret ever store or log my raw API keys in plain text?",
            a: "The browser sends vault credentials over HTTPS to the trusted broker, which encrypts them at rest with a separate AES-GCM key. Upstream keys exist in broker memory. Logs exclude credential values; reflected known strings are scrubbed as defense in depth.",
          },
          {
            q: "What is the difference between Bitwarden Secrets Manager and Bitwarden Password Manager?",
            a: "Bitwarden Secrets Manager uses a machine-account token in the broker. Bitwarden Password Manager stays behind an owner-bound local companion and is not unlocked in the cloud.",
          },
          {
            q: "How does AgentSecret prevent the LLM from leaking credentials?",
            a: "The API exposes aliases and approved requests instead of raw credentials. Scope and destination policies limit what a compromised agent can ask for. The approved upstream is trusted; sanitization cannot stop every possible encoding of a secret by a malicious upstream.",
          },
          {
            q: "Can I self-host AgentSecret or run on-premise?",
            a: "Deploy the Worker and SQLite Durable Object to your own Cloudflare account after configuring keys and identity policy. The local test runtime uses workerd. A generic on-premise deployment is not supplied.",
          },
        ].map((faq, i) => (
          <div
            key={i}
            style={{
              border: "1px solid #e2e8f0",
              borderRadius: "8px",
              background: "#ffffff",
              overflow: "hidden",
            }}
          >
            <button
              onClick={() => setOpenFaq(openFaq === i ? null : i)}
              style={{
                width: "100%",
                padding: "16px 20px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                background: "transparent",
                border: "none",
                cursor: "pointer",
                textAlign: "left",
                fontWeight: 700,
                fontSize: "14px",
                color: "#0f172a",
              }}
            >
              <span>{faq.q}</span>
              <span style={{ fontSize: "18px", color: "#94a3b8" }}>
                {openFaq === i ? "−" : "+"}
              </span>
            </button>
            {openFaq === i && (
              <div
                style={{
                  padding: "0 20px 16px 20px",
                  fontSize: "13px",
                  color: "#475569",
                  lineHeight: 1.6,
                }}
              >
                {faq.a}
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
