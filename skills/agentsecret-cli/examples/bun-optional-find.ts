import { fileURLToPath } from "node:url";

const cliPath = fileURLToPath(
  new URL("../../../dist/cli.mjs", import.meta.url),
);
const nodeExecutable = Bun.env.AGENTSECRET_NODE || "node";

function exactKeys(
  value: unknown,
  keys: string[],
): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === [...keys].sort().join(",")
  );
}

function invokeCli(args: string[]) {
  let result: ReturnType<typeof Bun.spawnSync>;
  try {
    result = Bun.spawnSync([nodeExecutable, cliPath, ...args], {
      env: { ...process.env },
    });
  } catch {
    throw new Error("AgentSecret companion could not be started.");
  }
  let receipt: unknown;
  try {
    receipt = JSON.parse(result.stdout.toString());
  } catch {
    throw new Error("AgentSecret returned an invalid result.");
  }
  return { code: result.exitCode, receipt };
}

function emit(value: Record<string, string>) {
  process.stdout.write(JSON.stringify(value) + "\n");
}

function main() {
  const alias = Bun.env.AGENTSECRET_ALIAS;
  if (!alias || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias))
    throw new Error("Set AGENTSECRET_ALIAS to an owner-approved alias.");

  const readiness = invokeCli(["ensure"]);
  const state = readiness.receipt;
  if (
    readiness.code === 1 &&
    exactKeys(state, ["status", "reason"]) &&
    state.status === "setup_needed" &&
    state.reason === "authentication_required_or_unavailable"
  ) {
    emit({ status: "setup_needed" });
    return;
  }
  if (
    readiness.code === 1 &&
    exactKeys(state, ["status", "reason"]) &&
    state.status === "not_ready" &&
    ["remote_session_rejected", "remote_status_unavailable"].includes(
      String(state.reason),
    )
  ) {
    emit({ status: "not_ready", reason: String(state.reason) });
    return;
  }
  if (
    readiness.code === 1 &&
    exactKeys(state, ["status"]) &&
    state.status === "invalid_local_session"
  ) {
    emit({ status: "invalid_local_session" });
    return;
  }
  if (
    readiness.code !== 0 ||
    !exactKeys(state, [
      "status",
      "server",
      "expiresAt",
      "remoteVerification",
    ]) ||
    state.status !== "ready" ||
    typeof state.server !== "string" ||
    !Number.isSafeInteger(state.expiresAt) ||
    state.remoteVerification !== "authenticated"
  )
    throw new Error("AgentSecret readiness check failed.");

  const lookup = invokeCli(["secrets", "find", "--alias", alias, "--optional"]);
  if (lookup.code !== 0)
    throw new Error("AgentSecret reference lookup failed.");
  const receipt = lookup.receipt;
  if (
    exactKeys(receipt, ["status"]) &&
    receipt.status === "optional_not_found"
  ) {
    emit({ status: "optional_not_found" });
    return;
  }
  if (
    !exactKeys(receipt, ["status", "provider", "reference"]) ||
    receipt.status !== "available" ||
    typeof receipt.provider !== "string" ||
    typeof receipt.reference !== "string"
  )
    throw new Error("AgentSecret returned an invalid reference receipt.");

  emit({ status: "available", reference: receipt.reference });
}

try {
  main();
} catch (error) {
  const safeMessages = new Set([
    "Set AGENTSECRET_ALIAS to an owner-approved alias.",
    "AgentSecret companion could not be started.",
    "AgentSecret returned an invalid result.",
    "AgentSecret readiness check failed.",
    "AgentSecret reference lookup failed.",
    "AgentSecret returned an invalid reference receipt.",
  ]);
  const message = error instanceof Error ? error.message : "";
  process.stderr.write(
    (safeMessages.has(message) ? message : "AgentSecret lookup failed.") + "\n",
  );
  process.exitCode = 1;
}
