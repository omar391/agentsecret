import type { AppController } from "../app/useAppController";
import { Check } from "lucide-react";

const INCLUDED = [
  "Multiple vault connections per account",
  "Alias policies with exact domain, method and path rules",
  "Owner-approved executors and short-lived browser grants",
  "Audit trail of broker decisions",
  "Local companion CLI and stdio MCP server",
];

export function Plan({ c }: { c: AppController }) {
  const { setShowAuthModal, setView, user } = c;
  return (
    <section id="pricing" className="section section-alt">
      <div className="container">
        <div className="section-head">
          <span className="eyebrow">Plan</span>
          <h2 className="h1">Self-hosted operation</h2>
          <p className="muted">
            This profile has no paid plans or checkout. The operator configures
            a monthly tenant allowance; Cloudflare and vault-provider costs are
            separate.
          </p>
        </div>
        <div className="card stack" style={{ maxWidth: 520, margin: "0 auto" }}>
          <div className="row-between">
            <div>
              <div className="h2">Free</div>
              <p className="subtle">
                Within the operator&apos;s monthly allowance
              </p>
            </div>
            <span className="badge badge-success">No card required</span>
          </div>
          <ul className="stack-sm" style={{ listStyle: "none" }}>
            {INCLUDED.map((item) => (
              <li
                key={item}
                className="row small"
                style={{ gap: 8, flexWrap: "nowrap" }}
              >
                <Check size={16} color="var(--accent)" />
                {item}
              </li>
            ))}
          </ul>
          <button
            type="button"
            className="btn btn-primary btn-block"
            onClick={() =>
              user ? setView("dashboard") : setShowAuthModal(true)
            }
          >
            {user ? "Open Dashboard" : "Create a free account"}
          </button>
        </div>
      </div>
    </section>
  );
}
