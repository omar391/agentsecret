import type { AppController } from "../../app/useAppController";
import { FindSecretForm } from "../secrets/FindSecretForm";
import { PrivateInputRequests } from "../secrets/PrivateInputRequests";
import { SaveSecretForm } from "../secrets/SaveSecretForm";

export function SecretsTab({ c }: { c: AppController }) {
  const {
    findResult,
    findStatus,
    saveMode,
    saveStatus,
    savedReference,
    vaultConnections,
  } = c;
  return (
    <section
      aria-labelledby="save-secret-heading"
      style={{
        background: "#ffffff",
        border: "1px solid #e2e8f0",
        borderRadius: "8px",
        padding: "24px",
        boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
      }}
    >
      <h2
        id="save-secret-heading"
        style={{ fontSize: "18px", margin: "0 0 6px" }}
      >
        Save secret
      </h2>
      <p style={{ color: "#64748b", fontSize: "13px" }}>
        Create a concealed secure note or update one exact field in the selected
        1Password Connect vault. The secret value is sent only with this
        authenticated request and is never stored in browser storage or returned
        by the service.
      </p>
      <p style={{ color: "#64748b", fontSize: "12px" }}>
        Writes are verified by reading the selected field back. Updates do not
        have a conditional-write guarantee. Other provider modes are not
        available here.
      </p>

      <FindSecretForm c={c} />
      {findStatus === "found" && findResult && (
        <p role="status">
          Reference is available in {findResult.provider}:{" "}
          {findResult.reference}. Secret values are never returned here.
        </p>
      )}
      {findStatus === "error" && (
        <p role="alert">Reference could not be verified for this connection.</p>
      )}

      <PrivateInputRequests c={c} />

      <SaveSecretForm c={c} />

      {vaultConnections.filter(
        (connection) =>
          connection.provider === "onepassword-connect" &&
          (saveMode === "delete"
            ? connection.capabilities?.delete === true
            : saveMode === "update"
              ? connection.capabilities?.update === true
              : connection.capabilities?.create === true),
      ).length === 0 && (
        <p role="status" style={{ color: "#64748b" }}>
          No {saveMode}-capable connection is connected. Add a 1Password Connect
          connection with this capability in Vault Connections first.
        </p>
      )}
      {saveStatus === "saved" && (
        <div role="status" style={{ marginTop: "18px" }}>
          <strong>
            {saveMode === "delete"
              ? "Secret field deleted"
              : `Secret ${saveMode === "update" ? "updated" : "created"}`}{" "}
            and verified.
          </strong>
          <div>{saveMode === "delete" ? "Deleted" : "Saved"} reference:</div>
          <code>{savedReference}</code>
        </div>
      )}
      {saveStatus === "error" && (
        <p role="alert">
          The operation failed. Check the selected connection and target, then
          try again.
        </p>
      )}
      {saveStatus === "unknown" && (
        <p role="alert">
          The operation outcome is not confirmed. Retry safely to check the same
          operation, or inspect the selected vault before starting a different
          operation.
        </p>
      )}
    </section>
  );
}
