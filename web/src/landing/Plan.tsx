import type { AppController } from "../app/useAppController";

export function Plan({ c }: { c: AppController }) {
  void c;
  return (
    <section
      id="pricing"
      style={{
        maxWidth: "1080px",
        margin: "50px auto",
        padding: "24px",
        width: "100%",
        border: "1px solid #e2e8f0",
        borderRadius: "8px",
      }}
    >
      <h2>Self-hosted operation</h2>
      <p>
        This profile has no paid plans or checkout. The operator configures a
        monthly tenant allowance; Cloudflare and vault-provider costs are
        separate.
      </p>
    </section>
  );
}
