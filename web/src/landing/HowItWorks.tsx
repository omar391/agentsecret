const STEPS = [
  {
    title: "Connect Your Vault",
    body: (
      <>
        Connect Bitwarden Secrets Manager directly, or bind a Bitwarden Password
        Manager, 1Password service account, or LastPass companion locally. The
        broker encrypts cloud connection metadata at rest with AES-256-GCM.
      </>
    ),
  },
  {
    title: "Define Whitelist Policies",
    body: (
      <>
        Map secret aliases to strict target domains and HTTP methods (e.g.{" "}
        <code className="code-inline">GITHUB_API</code> can only communicate
        with <code className="code-inline">api.github.com</code>).
      </>
    ),
  },
  {
    title: "Point Your Agents",
    body: (
      <>
        Use the authenticated companion with an agent that supports local stdio
        MCP. The cloud returns bounded API results; it does not execute a native
        command on your device.
      </>
    ),
  },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="section section-alt">
      <div className="container">
        <div className="section-head">
          <span className="eyebrow">Simple 3-Step Architecture</span>
          <h2 className="h1">How AgentSecret Works</h2>
        </div>
        <div className="grid-3">
          {STEPS.map((step, index) => (
            <div key={step.title} className="card feature-card">
              <span className="step-number">{index + 1}</span>
              <h3 className="h3">{step.title}</h3>
              <p className="muted">{step.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
