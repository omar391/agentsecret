import type { AppController } from "../../app/useAppController";
import { PageHeader } from "../PageHeader";

export function CompanionTab({ c }: { c: AppController }) {
  const origin = window.location.origin;
  const tenant = c.user ? ` --tenant ${c.user.id}` : "";
  return (
    <>
      <PageHeader
        title="Authorize a companion"
        description="Run the companion login and approve only a request you initiated. Headless devices use a confirmation code; CI uses configured workload federation."
      />
      <section className="card stack">
        <div className="stack-sm">
          <span className="eyebrow">Interactive or headless login</span>
          <pre className="code-block">{`agentsecret login --server ${origin}${tenant} --aliases API_TOKEN
agentsecret login --server ${origin}${tenant} --device --aliases API_TOKEN`}</pre>
        </div>
        <p className="notice">
          No OAuth token simulator or raw credential export is available.
        </p>
      </section>
    </>
  );
}
