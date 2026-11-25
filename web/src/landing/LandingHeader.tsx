import { useState } from "react";
import type { AppController } from "../app/useAppController";
import { Menu, Shield, X } from "lucide-react";

const LINKS = [
  { href: "#how-it-works", label: "How It Works" },
  { href: "#integrations", label: "Integrations" },
  { href: "#pricing", label: "Plan" },
  { href: "#faq", label: "FAQ" },
];

export function LandingHeader({ c }: { c: AppController }) {
  const { setShowAuthModal, setView, user } = c;
  const [menuOpen, setMenuOpen] = useState(false);
  const start = () => (user ? setView("dashboard") : setShowAuthModal(true));
  return (
    <header className="site-header">
      <div
        className="container site-header-inner"
        style={{ position: "relative" }}
      >
        <button
          type="button"
          className="brand"
          onClick={() => setView("landing")}
          aria-label="AgentSecret home"
        >
          <span className="brand-mark">
            <Shield size={16} strokeWidth={2.4} />
          </span>
          AgentSecret
        </button>

        <nav
          id="site-nav"
          className="site-nav"
          data-open={menuOpen}
          aria-label="Primary"
        >
          {LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              onClick={() => setMenuOpen(false)}
            >
              {link.label}
            </a>
          ))}
        </nav>

        <div className="site-actions">
          <button
            type="button"
            className="btn btn-ghost hide-mobile"
            onClick={() => setShowAuthModal(true)}
          >
            Sign in
          </button>
          <button type="button" className="btn btn-primary" onClick={start}>
            {user ? "Open Dashboard" : "Get Started Free"}
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-icon menu-toggle"
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            aria-expanded={menuOpen}
            aria-controls="site-nav"
            onClick={() => setMenuOpen(!menuOpen)}
          >
            {menuOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>
      </div>
    </header>
  );
}
