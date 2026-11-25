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
      <h3 style={{ margin: 0, fontSize: "14px" }}>Find by reference</h3>
      <label>
        Read connection
        <select
          aria-label="Find connection"
          required
          value={findConnectionId}
          onChange={(e) => {
            findRequestVersion.current++;
            setFindConnectionId(e.target.value);
            setFindStatus("idle");
            setFindResult(null);
          }}
          style={{
            display: "block",
            width: "100%",
            marginTop: "6px",
          }}
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
      <label>
        Secret reference
        <input
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
        className="btn-tactile"
        style={{
          justifySelf: "start",
          background: "#ffffff",
          color: "#0f172a",
          border: "1px solid #cbd5e1",
          borderRadius: "6px",
          padding: "9px 16px",
          fontWeight: 600,
        }}
      >
        {findStatus === "searching" ? "Checking…" : "Find secret"}
      </button>
    </form>
  );
}
