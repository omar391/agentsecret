import type { AppController } from "../app/useAppController";
import { Faq } from "./Faq";
import { Hero } from "./Hero";
import { HowItWorks } from "./HowItWorks";
import { LandingFooter } from "./LandingFooter";
import { LandingHeader } from "./LandingHeader";
import { LandingIntegrations } from "./LandingIntegrations";
import { Plan } from "./Plan";

export function LandingPage({ c }: { c: AppController }) {
  void c;
  return (
    <div
      className="white-minimal-grid"
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
      }}
    >
      {/* Clean, Uncluttered Top Navbar */}
      <LandingHeader c={c} />

      {/* Sales Funnel Hero Section */}
      <Hero c={c} />

      {/* ─────────────────────────────────────────────────────────────
          FUNNEL SECTION 3: HOW IT WORKS IN 3 STEPS
         ───────────────────────────────────────────────────────────── */}
      <HowItWorks c={c} />

      {/* ─────────────────────────────────────────────────────────────
          FUNNEL SECTION 4: INTEGRATIONS
         ───────────────────────────────────────────────────────────── */}
      <LandingIntegrations c={c} />

      {/* ─────────────────────────────────────────────────────────────
          FUNNEL SECTION 5: PRICING (Clean, Transparent, No Slop)
         ───────────────────────────────────────────────────────────── */}
      <Plan c={c} />

      {/* ─────────────────────────────────────────────────────────────
          FUNNEL SECTION 6: FAQ ACCORDION
         ───────────────────────────────────────────────────────────── */}
      <Faq c={c} />

      {/* Footer */}
      <LandingFooter c={c} />
    </div>
  );
}
