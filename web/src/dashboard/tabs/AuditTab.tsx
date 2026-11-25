import type { AppController } from "../../app/useAppController";

export function AuditTab({ c }: { c: AppController }) {
  const { auditLogs } = c;
  return (
    <section
      style={{
        background: "#fff",
        border: "1px solid #e2e8f0",
        borderRadius: 8,
        padding: 24,
      }}
    >
      <h3>Broker audit trail</h3>
      <p>
        Recent completed requests. Credentials, bodies and query values are
        excluded.
      </p>
      <table style={{ width: "100%", textAlign: "left", fontSize: 12 }}>
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
              <td>{log.at}</td>
              <td>{log.alias}</td>
              <td>{log.host}</td>
              <td>{log.method}</td>
              <td>{log.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!auditLogs.length && <p>No audit records are available.</p>}
    </section>
  );
}
