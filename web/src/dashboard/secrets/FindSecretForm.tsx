import type { AppController } from "../../app/useAppController";

export function FindSecretForm({ c }: { c: AppController }) {
  const {
    findConnectionId,
    findReference,
    findRequestVersion,
    findStatus,
    handleFindSecret,
    setFindConnectionId,
    setFindReference,
    setFindResult,
    setFindStatus,
    vaultConnections,
  } = c;
  return (
    <form
      aria-label="Find secret by reference"
      onSubmit={handleFindSecret}
      style={{
        display: "grid",
        gap: "14px",
        maxWidth: "560px",
        padding: "16px 0 20px",
        borderBottom: "1px solid #e2e8f0",
      }}
    >
      <h2 className="card-title">Find by reference</h2>
      <label className="field">
        Read connection
        <select
          className="select"
          aria-label="Find connection"
          required
          value={findConnectionId}
          onChange={(e) => {
            findRequestVersion.current++;
            setFindConnectionId(e.target.value);
            setFindStatus("idle");
            setFindResult(null);
          }}
          style={{ width: "100%" }}
        >
          <option value="">Choose a connection</option>
          {vaultConnections.map((connection) => (
            <option
              key={connection.id}
              value={connection.id}
              disabled={!connection.capabilities?.read}
            >
              {connection.alias} — {connection.provider} —{" "}
              {connection.capabilities?.read
                ? "read available"
                : "read unavailable"}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        Secret reference
        <input
          className="input"
          aria-label="Secret reference"
          value={findReference}
          maxLength={1024}
          required
          autoComplete="off"
          onChange={(e) => {
            findRequestVersion.current++;
            setFindReference(e.target.value);
            setFindStatus("idle");
            setFindResult(null);
          }}
        />
      </label>
      <button
        type="submit"
        disabled={
          findStatus === "searching" ||
          !findConnectionId ||
          !findReference.trim()
        }
        className="btn btn-secondary"
        style={{ justifySelf: "start" }}
      >
        {findStatus === "searching" ? "Checking…" : "Find secret"}
      </button>
    </form>
  );
}
