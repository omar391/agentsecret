import type { AppController } from "../../app/useAppController";
import { CheckCircle, Copy, Key } from "lucide-react";
import { PageHeader } from "../PageHeader";

export function OverviewTab({ c }: { c: AppController }) {
  const { copiedKey, copyToClipboard, policies, user } = c;
  const used = user?.quotaUsed ?? 0;
  const limit = user?.quotaLimit || 0;
  const percent = limit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  const loginCommand = "agentsecret login --server " + window.location.origin;
  return (
    <>
      <PageHeader
        title="Overview"
        description="Your allowance, policies and how agents reach this broker."
      />
      <div className="grid-4">
        <div className="card card-tight stack-sm">
          <span className="eyebrow">Monthly Quota</span>
          <div className="stat-value">
            {user?.quotaUsed?.toLocaleString() ?? "0"} /{" "}
            {user?.quotaLimit?.toLocaleString() ?? "—"}
          </div>
          <div
            className="meter"
            role="progressbar"
            aria-label="Monthly allowance used"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent}
          >
            <span style={{ width: percent + "%" }} />
          </div>
        </div>

        <div className="card card-tight stack-sm">
          <span className="eyebrow">Configured Policies</span>
          <div className="stat-value">{policies.length} Active</div>
          <span className="subtle">Domain and method policies</span>
        </div>

        <div className="card card-tight stack-sm">
          <span className="eyebrow">Stored credentials</span>
          <div className="stat-value">Encrypted</div>
          <span className="subtle">Server-side AES-256-GCM envelope</span>
        </div>

        <div className="card card-tight stack-sm">
          <span className="eyebrow">Credential handling</span>
          <div className="stat-value">Strict broker</div>
          <span className="subtle">
            Agents get aliases; values stay in the broker or companion
          </span>
        </div>
      </div>

      <section className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title row" style={{ gap: 8 }}>
              <Key size={16} color="var(--accent)" /> Companion authentication
            </h2>
            <p className="card-desc">
              Authorize the companion with explicit aliases. It stores a DPoP
              key in the operating-system credential store and signs each broker
              request.
            </p>
          </div>
          <span className="badge badge-success">Device-bound session</span>
        </div>
        <div className="row" style={{ flexWrap: "nowrap" }}>
          <input
            className="input input-mono"
            type="text"
            readOnly
            aria-label="Companion login command"
            value={loginCommand}
            style={{ flex: 1 }}
          />
          <button
            type="button"
            className={"btn " + (copiedKey ? "btn-accent" : "btn-primary")}
            onClick={() => copyToClipboard(loginCommand, "apiKey")}
          >
            {copiedKey ? <CheckCircle size={14} /> : <Copy size={14} />}
            {copiedKey ? "Copied" : "Copy"}
          </button>
        </div>
      </section>
    </>
  );
}
