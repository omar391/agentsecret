import type { AppController } from "../app/useAppController";
import { ChevronDown } from "lucide-react";

const FAQS = [
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
    a: "Yes. Run the self-hosted Node/SQLite server from the Corresponding Source (npm run serve), or deploy the Worker and SQLite Durable Object to your own Cloudflare account after configuring keys and identity policy.",
  },
];

export function Faq({ c }: { c: AppController }) {
  const { openFaq, setOpenFaq } = c;
  return (
    <section id="faq" className="section">
      <div className="container" style={{ maxWidth: 760 }}>
        <div className="section-head">
          <span className="eyebrow">FAQ</span>
          <h2 className="h1">Frequently Asked Questions</h2>
        </div>
        <div className="stack-sm">
          {FAQS.map((faq, i) => {
            const open = openFaq === i;
            return (
              <div key={faq.q} className="faq-item">
                <button
                  type="button"
                  className="faq-question"
                  aria-expanded={open}
                  aria-controls={"faq-answer-" + i}
                  onClick={() => setOpenFaq(open ? null : i)}
                >
                  <span>{faq.q}</span>
                  <ChevronDown
                    size={18}
                    aria-hidden="true"
                    style={{
                      transform: open ? "rotate(180deg)" : undefined,
                      transition: "transform 0.15s ease",
                    }}
                  />
                </button>
                {open && (
                  <div id={"faq-answer-" + i} className="faq-answer">
                    {faq.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
