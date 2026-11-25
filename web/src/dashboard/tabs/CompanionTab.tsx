import type { AppController } from "../../app/useAppController";

export function CompanionTab({ c }: { c: AppController }) {
  void c;
  return (
    <section>
      <h2>Authorize a companion</h2>
      <p>
        Run the companion login and approve only a request you initiated.
        Headless devices use a confirmation code; CI uses configured workload
        federation.
      </p>
      <pre>{`agentsecret login --server ${window.location.origin} --aliases API_TOKEN
    agentsecret login --server ${window.location.origin} --device --aliases API_TOKEN`}</pre>
      <p>No OAuth token simulator or raw credential export is available.</p>
    </section>
  );
}
