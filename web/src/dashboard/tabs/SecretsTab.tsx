import type { AppController } from "../../app/useAppController";
import { FindSecretForm } from "../secrets/FindSecretForm";
import { PrivateInputRequests } from "../secrets/PrivateInputRequests";
import { SaveSecretForm } from "../secrets/SaveSecretForm";
import { PageHeader } from "../PageHeader";

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
    <>
      <PageHeader
        title="Secrets"
        description="Find, save and fulfil agent requests against exact provider references. Secret values are never shown here after you submit them."
      />
      <section className="card stack" aria-label="Find secret">
        <FindSecretForm c={c} />
        {findStatus === "found" && findResult && (
          <p className="notice notice-success" role="status">
            Reference is available in {findResult.provider}:{" "}
            {findResult.reference}. Secret values are never returned here.
          </p>
        )}
        {findStatus === "error" && (
          <p className="notice notice-error" role="alert">
            Reference could not be verified for this connection.
          </p>
        )}
      </section>
      <PrivateInputRequests c={c} />
      <section className="card stack" aria-labelledby="save-secret-heading">
        <div>
          <h2 className="card-title" id="save-secret-heading">
            Save secret
          </h2>
          <p className="card-desc">
            Create a concealed secure note or update one exact field in the
            selected 1Password Connect vault. The secret value is sent only with
            this authenticated request and is never stored in browser storage or
            returned by the service.
          </p>
          <p className="card-desc">
            Writes are verified by reading the selected field back. Updates do
            not have a conditional-write guarantee. Bitwarden Secrets Manager
            connections are read-only here; password-manager stores are written
            only through the owner-approved local companion.
          </p>
        </div>
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
          <p className="notice notice-warn" role="status">
            No {saveMode}-capable connection is connected. Add a 1Password
            Connect connection with this capability in Vault Connections first.
          </p>
        )}
        {saveStatus === "saved" && (
          <div className="notice notice-success" role="status">
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
          <p className="notice notice-error" role="alert">
            The operation failed. Check the selected connection and target, then
            try again.
          </p>
        )}
        {saveStatus === "unknown" && (
          <p className="notice notice-error" role="alert">
            The operation outcome is not confirmed. Retry safely to check the
            same operation, or inspect the selected vault before starting a
            different operation.
          </p>
        )}
      </section>
    </>
  );
}
