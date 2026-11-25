import type { AppController } from "../../app/useAppController";

export function PrivateInputRequests({ c }: { c: AppController }) {
  const {
    handleFulfillPrivateInput,
    handleLoadMorePrivateInputs,
    privateInputDrafts,
    privateInputFeedback,
    privateInputLoadingMore,
    privateInputNextCursor,
    privateInputRequests,
    privateInputSubmitting,
    setPrivateInputDrafts,
    vaultConnections,
  } = c;
  return (
    <section
      className="card-flat"
      aria-labelledby="private-input-requests-heading"
      style={{ marginTop: "20px" }}
    >
      <h3 className="h3" id="private-input-requests-heading">
        Agent save requests
      </h3>
      <p className="subtle">
        Enter requested values here in your authenticated dashboard. Values are
        sent directly to the selected connection and are never returned to the
        requesting agent.
      </p>
      {privateInputRequests.length === 0 ? (
        <p className="muted">No pending requests.</p>
      ) : (
        <div style={{ display: "grid", gap: "14px" }}>
          {privateInputRequests.map((request) => {
            const connection = vaultConnections.find(
              (item) => item.id === request.connectionId,
            );
            const requestExpired =
              request.status === "pending" &&
              request.expiresAt * 1000 <= Date.now();
            return (
              <article
                key={request.requestId}
                style={{
                  paddingTop: "12px",
                  borderTop: "1px solid #e2e8f0",
                }}
              >
                <p style={{ fontSize: "13px" }}>
                  <strong>{request.intent}</strong> for alias{" "}
                  <strong>{request.alias}</strong> in{" "}
                  {connection?.alias ?? "the selected connection"}
                  {request.intent !== "create" ? (
                    <>
                      {" "}
                      at reference <code>{request.target}</code>
                    </>
                  ) : (
                    <>
                      {" "}
                      with title <strong>{request.target}</strong>
                    </>
                  )}
                </p>
                {request.status === "pending" &&
                !requestExpired &&
                connection?.provider === "onepassword-service-account" ? (
                  <p className="subtle">
                    This vault stays on your device. From the agent session that
                    created the request, complete it in the enrolled companion
                    with{" "}
                    <code>
                      agentsecret secrets fulfill --request-id{" "}
                      {request.requestId}
                    </code>
                    . The service-account value is never sent to this page.
                  </p>
                ) : request.status === "pending" && !requestExpired ? (
                  <form
                    aria-label={`Fulfill save request for ${request.alias}`}
                    onSubmit={(event) =>
                      handleFulfillPrivateInput(event, request)
                    }
                    style={{ display: "grid", gap: "8px" }}
                  >
                    <label className="field">
                      Secret value
                      <input
                        className="input"
                        type="password"
                        autoComplete="new-password"
                        required
                        maxLength={8192}
                        value={privateInputDrafts[request.requestId] ?? ""}
                        disabled={
                          privateInputSubmitting !== null ||
                          request.expiresAt * 1000 <= Date.now()
                        }
                        onChange={(event) =>
                          setPrivateInputDrafts((current) => ({
                            ...current,
                            [request.requestId]: event.target.value,
                          }))
                        }
                      />
                    </label>
                    <button
                      type="submit"
                      disabled={
                        !privateInputDrafts[request.requestId] ||
                        privateInputSubmitting !== null ||
                        request.expiresAt * 1000 <= Date.now()
                      }
                      className="btn btn-primary"
                      style={{ justifySelf: "start" }}
                    >
                      {privateInputSubmitting === request.requestId
                        ? "Saving…"
                        : request.intent === "ensure"
                          ? "Ensure field"
                          : "Save to vault"}
                    </button>
                  </form>
                ) : request.status === "saved" ? null : (
                  <p
                    role={
                      requestExpired || request.status === "fulfilling"
                        ? "status"
                        : "alert"
                    }
                    style={{ color: "#9a3412" }}
                  >
                    {requestExpired
                      ? "This request expired before it was fulfilled. The agent must submit a new request."
                      : request.status === "fulfilling"
                        ? "This write is in progress. Check this panel again shortly for its result."
                        : "The previous write outcome is unknown. Inspect the destination vault before asking the agent to start another save."}
                  </p>
                )}
                {privateInputFeedback[request.requestId] && (
                  <p
                    role={
                      /^(Saved and verified:|Updated and verified:|Already matched; no write was made:)/.test(
                        privateInputFeedback[request.requestId],
                      )
                        ? "status"
                        : "alert"
                    }
                  >
                    {privateInputFeedback[request.requestId]}
                  </p>
                )}
              </article>
            );
          })}
        </div>
      )}
      {privateInputNextCursor && (
        <button
          type="button"
          disabled={privateInputLoadingMore}
          onClick={() => void handleLoadMorePrivateInputs()}
          className="btn btn-ghost"
          style={{ justifySelf: "start" }}
        >
          {privateInputLoadingMore ? "Loading…" : "Show older requests"}
        </button>
      )}
    </section>
  );
}
