import type { AppController } from "../app/useAppController";
import { Faq } from "./Faq";
import { Hero } from "./Hero";
import { HowItWorks } from "./HowItWorks";
import { LandingFooter } from "./LandingFooter";
import { LandingHeader } from "./LandingHeader";
import { LandingIntegrations } from "./LandingIntegrations";
import { Plan } from "./Plan";

export function LandingPage({ c }: { c: AppController }) {
  return (
    <div className="landing">
      <LandingHeader c={c} />
      <main>
        <div className="landing-grid">
          <Hero c={c} />
        </div>
        <HowItWorks />
        <LandingIntegrations c={c} />
        <Plan c={c} />
        <Faq c={c} />
      </main>
      <LandingFooter c={c} />
    </div>
  );
}
