import type { AppController } from "../../app/useAppController";

export function SaveSecretForm({ c }: { c: AppController }) {
  const {
    compareRequestVersion,
    compareStatus,
    deleteConfirmed,
    ensureStatus,
    handleCompareSecret,
    handleEnsureSecret,
    handleSaveSecret,
    saveConnectionId,
    saveMode,
    saveReference,
    saveStatus,
    saveTitle,
    saveValue,
    setCompareStatus,
    setDeleteConfirmed,
    setEnsureStatus,
    setSaveConnectionId,
    setSaveMode,
    setSaveOperationId,
    setSaveReference,
    setSaveStatus,
    setSaveTitle,
    setSaveValue,
    setSavedReference,
    vaultConnections,
  } = c;
  return (
    <form
      aria-label="Save secret"
      onSubmit={handleSaveSecret}
      style={{
        display: "grid",
        gap: "16px",
        maxWidth: "560px",
        marginTop: "20px",
      }}
    >
      <label>
        Operation
        <select
          aria-label="Secret operation"
          value={saveMode}
          disabled={
            saveStatus === "saving" ||
            saveStatus === "unknown" ||
            compareStatus === "checking" ||
            ensureStatus === "checking" ||
            ensureStatus === "unknown"
          }
          onChange={(e) => {
            const mode = e.target.value as "create" | "update" | "delete";
            compareRequestVersion.current++;
            setCompareStatus("idle");
            setEnsureStatus("idle");
            setSaveMode(mode);
            setSaveOperationId("");
            setSavedReference("");
            setDeleteConfirmed(false);
            if (mode === "delete") setSaveValue("");
            setSaveStatus("idle");
          }}
          style={{
            display: "block",
            width: "100%",
            marginTop: "6px",
          }}
        >
          <option value="create">Create a new secret</option>
          <option value="update">Update an exact field</option>
          <option value="delete">Delete an exact field</option>
        </select>
      </label>
      <label>
        Destination connection
        <select
          aria-label="Destination connection"
          required
          value={saveConnectionId}
          disabled={
            saveStatus === "saving" ||
            saveStatus === "unknown" ||
            compareStatus === "checking" ||
            ensureStatus === "checking" ||
            ensureStatus === "unknown"
          }
          onChange={(e) => {
            compareRequestVersion.current++;
            setCompareStatus("idle");
            setEnsureStatus("idle");
            setSaveConnectionId(e.target.value);
            setSaveOperationId("");
            setSaveStatus("idle");
            setSavedReference("");
            setDeleteConfirmed(false);
          }}
          style={{
            display: "block",
            width: "100%",
            marginTop: "6px",
          }}
        >
          <option value="">Choose a connection</option>
          {vaultConnections.map((connection) => {
            const canCreate =
              connection.provider === "onepassword-connect" &&
              (saveMode === "delete"
                ? connection.capabilities?.delete === true
                : saveMode === "update"
                  ? connection.capabilities?.update === true
                  : connection.capabilities?.create === true);
            return (
              <option
                key={connection.id}
                value={connection.id}
                disabled={!canCreate}
              >
                {connection.alias} — {connection.provider} —{" "}
                {canCreate
                  ? `${saveMode} available`
                  : `${saveMode} unavailable`}
              </option>
            );
          })}
        </select>
      </label>

      {saveConnectionId && (
        <p
          style={{
            margin: 0,
            color: "#475569",
            fontSize: "12px",
          }}
        >
          Destination vault is the vault configured for this connection. Create
          and update write one item/field; delete removes only the exact field
          and preserves its containing item and sibling fields.
        </p>
      )}

      {saveMode === "update" || saveMode === "delete" ? (
        <label>
          {saveMode === "delete"
            ? "Exact field reference to delete"
            : "Exact field reference"}
          <input
            aria-label={
              saveMode === "delete"
                ? "Delete secret reference"
                : "Update secret reference"
            }
            value={saveReference}
            maxLength={1024}
            required
            autoComplete="off"
            disabled={
              saveStatus === "saving" ||
              saveStatus === "unknown" ||
              compareStatus === "checking" ||
              ensureStatus === "checking" ||
              ensureStatus === "unknown"
            }
            onChange={(e) => {
              compareRequestVersion.current++;
              setCompareStatus("idle");
              setEnsureStatus("idle");
              setSaveReference(e.target.value);
              setSaveOperationId("");
              setSavedReference("");
              setSaveStatus("idle");
              setDeleteConfirmed(false);
            }}
          />
        </label>
      ) : (
        <label>
          Item title
          <input
            aria-label="Secret title"
            value={saveTitle}
            maxLength={128}
            required
            autoComplete="off"
            disabled={saveStatus === "saving" || saveStatus === "unknown"}
            onChange={(e) => setSaveTitle(e.target.value)}
          />
        </label>
      )}
      {saveMode !== "delete" && (
        <label>
          Secret value
          <input
            aria-label="Secret value"
            type="password"
            value={saveValue}
            maxLength={8192}
            required
            autoComplete="new-password"
            disabled={
              saveStatus === "saving" ||
              saveStatus === "unknown" ||
              compareStatus === "checking" ||
              ensureStatus === "checking" ||
              ensureStatus === "unknown"
            }
            onChange={(e) => {
              compareRequestVersion.current++;
              setCompareStatus("idle");
              setEnsureStatus("idle");
              setSaveValue(e.target.value);
              setSavedReference("");
              setSaveStatus("idle");
            }}
          />
        </label>
      )}

      {saveMode === "update" && (
        <div style={{ display: "grid", gap: "8px" }}>
          <button
            type="button"
            disabled={
              compareStatus === "checking" ||
              ensureStatus === "checking" ||
              saveStatus === "saving" ||
              saveStatus === "unknown" ||
              !saveConnectionId ||
              !saveReference.trim() ||
              !saveValue ||
              !vaultConnections.find(
                (connection) =>
                  connection.id === saveConnectionId &&
                  connection.capabilities?.read === true,
              )
            }
            onClick={() => void handleCompareSecret()}
            className="btn-tactile"
            style={{
              justifySelf: "start",
              background: "#ffffff",
              color: "#0f172a",
              border: "1px solid #cbd5e1",
              borderRadius: "6px",
              padding: "8px 14px",
              fontWeight: 600,
            }}
          >
            {compareStatus === "checking" ? "Comparing…" : "Compare privately"}
          </button>
          <p
            style={{
              margin: 0,
              color: "#64748b",
              fontSize: "12px",
            }}
          >
            Owner-only comparison against the exact field. Compare privately
            never writes; Ensure field writes only when values differ, then
            verifies the update. Agents cannot call either operation.
          </p>
          {compareStatus === "match" && (
            <p role="status">
              The entered value matches the field. No write was made.
            </p>
          )}
          {compareStatus === "different" && (
            <p role="status">
              The entered value differs from the field. No write was made.
            </p>
          )}
          {compareStatus === "error" && (
            <p role="alert">The value could not be compared with this field.</p>
          )}
          <button
            type="button"
            disabled={
              ensureStatus === "checking" ||
              compareStatus === "checking" ||
              saveStatus === "saving" ||
              !saveConnectionId ||
              !saveReference.trim() ||
              !saveValue ||
              !vaultConnections.find(
                (connection) =>
                  connection.id === saveConnectionId &&
                  connection.provider === "onepassword-connect" &&
                  connection.capabilities?.read === true &&
                  connection.capabilities?.update === true,
              )
            }
            onClick={() => void handleEnsureSecret()}
            className="btn-tactile"
            style={{
              justifySelf: "start",
              background: "#ffffff",
              color: "#0f172a",
              border: "1px solid #cbd5e1",
              borderRadius: "6px",
              padding: "8px 14px",
              fontWeight: 600,
            }}
          >
            {ensureStatus === "checking"
              ? "Ensuring…"
              : ensureStatus === "unknown"
                ? "Retry ensure safely"
                : "Ensure field"}
          </button>
          {ensureStatus === "unchanged" && (
            <p role="status">The field already matches. No write was made.</p>
          )}
          {ensureStatus === "updated" && (
            <p role="status">
              The field differed, so it was updated and verified.
            </p>
          )}
          {ensureStatus === "unknown" && (
            <p role="alert">
              The update outcome is unknown. Retry the same ensure operation to
              retrieve its receipt, or inspect the selected vault before
              starting another operation.
            </p>
          )}
          {ensureStatus === "error" && (
            <p role="alert">
              The field could not be ensured. Check the selected connection and
              reference, then try again.
            </p>
          )}
        </div>
      )}

      {saveMode === "delete" && (
        <label style={{ display: "flex", gap: "8px" }}>
          <input
            aria-label="Confirm exact field deletion"
            type="checkbox"
            checked={deleteConfirmed}
            disabled={saveStatus === "saving" || saveStatus === "unknown"}
            onChange={(e) => setDeleteConfirmed(e.target.checked)}
          />
          I understand that this permanently removes the referenced field.
        </label>
      )}

      <button
        type="submit"
        disabled={
          saveStatus === "saving" ||
          compareStatus === "checking" ||
          ensureStatus === "checking" ||
          !saveConnectionId ||
          (saveMode === "update" || saveMode === "delete"
            ? !saveReference.trim()
            : !saveTitle.trim()) ||
          (saveMode !== "delete" && !saveValue) ||
          (saveMode === "delete" && !deleteConfirmed)
        }
        className="btn-tactile"
        style={{
          justifySelf: "start",
          background: "#0f172a",
          color: "#ffffff",
          border: "none",
          borderRadius: "6px",
          padding: "10px 18px",
          fontWeight: 600,
          cursor: saveStatus === "saving" ? "wait" : "pointer",
        }}
      >
        {saveStatus === "saving"
          ? "Saving…"
          : saveStatus === "unknown"
            ? "Retry safely"
            : saveMode === "delete"
              ? "Delete field"
              : saveMode === "update"
                ? "Update field"
                : "Create secret"}
      </button>
    </form>
  );
}
