import type { AppController } from "../../app/useAppController";
import { formatTimestamp } from "../../ui/format";
import { PageHeader } from "../PageHeader";

function statusBadge(status: number): string {
  if (status >= 200 && status < 300) return "badge badge-success";
  if (status >= 400 && status < 500) return "badge badge-warn";
  if (status >= 500) return "badge badge-danger";
  return "badge";
}

export function AuditTab({ c }: { c: AppController }) {
  const { auditLogs } = c;
  return (
    <>
      <PageHeader
        title="Audit Trail"
        description="Recent completed requests. Credentials, bodies and query values are excluded."
      />
      <section className="card" aria-label="Broker audit trail">
        {auditLogs.length === 0 ? (
          <p className="empty-state">
            <strong>No audit records are available.</strong>
            Requests appear here after an agent uses an alias.
          </p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Alias</th>
                  <th>Domain</th>
                  <th>Method</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log, i) => (
                  <tr key={i}>
                    <td className="subtle" style={{ whiteSpace: "nowrap" }}>
                      <time dateTime={log.at}>{formatTimestamp(log.at)}</time>
                    </td>
                    <td>
                      <code className="code-inline">{log.alias}</code>
                    </td>
                    <td className="break">{log.host}</td>
                    <td>{log.method}</td>
                    <td>
                      <span className={statusBadge(log.status)}>
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
