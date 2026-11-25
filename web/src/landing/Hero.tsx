import type { AppController } from "../app/useAppController";
import { ArrowRight, Database, KeyRound, Lock, Route } from "lucide-react";

const FACTS = [
  {
    icon: <KeyRound size={18} />,
    label: "Credential delivery",
    value: "Brokered",
    detail:
      "Agents hold aliases; secret values stay in the broker or a local companion.",
  },
  {
    icon: <Route size={18} />,
    label: "Request policy",
    value: "Allowlisted",
    detail: "Exact HTTPS domain, method and path rules per alias.",
  },
  {
    icon: <Lock size={18} />,
    label: "Agent credentials",
    value: "DPoP-bound",
    detail: "Each agent session is tied to a key it must prove it holds.",
  },
  {
    icon: <Database size={18} />,
    label: "Vaults",
    value: "Bring your own",
    detail:
      "Bitwarden and 1Password service accounts, plus owner-approved local companions.",
  },
];

export function Hero({ c }: { c: AppController }) {
  const { setShowAuthModal, setView, user } = c;
  return (
    <section className="hero">
      <div className="container hero-inner">
        <span className="pill">
          <span className="dot dot-success" />
          Policy-bound secret broker
        </span>
        <h1 className="hero-title">
          Give agents approved API access through secret aliases.
        </h1>
        <p className="hero-sub">
          AgentSecret uses <strong>Bitwarden Secrets Manager</strong>,{" "}
          <strong>1Password service accounts</strong>, or an owner-bound local
          password-manager companion. Agents receive scoped results through
          aliases. The operator, broker, device, companion, and approved
          upstream remain trust boundaries.
        </p>
        <div className="row" style={{ justifyContent: "center" }}>
          <button
            type="button"
            className="btn btn-primary btn-lg"
            onClick={() =>
              user ? setView("dashboard") : setShowAuthModal(true)
            }
          >
            Start Securing Agents Free <ArrowRight size={17} />
          </button>
          <a href="#how-it-works" className="btn btn-secondary btn-lg">
            How it works
          </a>
        </div>
        <p className="subtle">
          Self-hosted · Operator-configured monthly allowance
        </p>

        <div
          className="grid-4"
          style={{ width: "100%", marginTop: 24, textAlign: "left" }}
        >
          {FACTS.map((fact) => (
            <div key={fact.label} className="card card-tight feature-card">
              <span className="feature-icon">{fact.icon}</span>
              <div>
                <div className="eyebrow">{fact.label}</div>
                <div className="h3" style={{ marginTop: 2 }}>
                  {fact.value}
                </div>
              </div>
              <p className="subtle">{fact.detail}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
