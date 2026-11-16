import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

// This app invokes the packaged CLI as a subprocess; it imports no AgentSecret SDK.
const cliPath = fileURLToPath(
  new URL("../../../dist/cli.mjs", import.meta.url),
);
function invokeCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    const fail = (message) => {
      if (settled) return;
      settled = true;
      child.kill("SIGTERM");
      reject(new Error(message));
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > 64 * 1024) {
        fail("AgentSecret returned an oversized result.");
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 16 * 1024)
        fail("AgentSecret returned oversized diagnostics.");
    });
    child.once("error", () => fail("AgentSecret could not be started."));
    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      try {
        resolve({
          code,
          result: JSON.parse(Buffer.concat(stdout).toString("utf8")),
        });
      } catch {
        reject(new Error("AgentSecret returned an invalid result."));
      }
    });
  });
}

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === [...keys].sort().join(",")
  );
}

async function main() {
  const alias = process.env.AGENTSECRET_ALIAS;
  if (!alias || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias))
    throw new Error("Set AGENTSECRET_ALIAS to an owner-approved alias.");
  const optional = process.env.AGENTSECRET_OPTIONAL;
  if (optional !== undefined && optional !== "1")
    throw new Error(
      "Set AGENTSECRET_OPTIONAL to 1 to allow a missing reference.",
    );

  const readiness = await invokeCli(["ensure"]);
  const state = readiness.result;
  if (
    readiness.code === 1 &&
    exactKeys(state, ["status", "reason"]) &&
    state.status === "setup_needed" &&
    state.reason === "authentication_required_or_unavailable"
  ) {
    process.stdout.write(JSON.stringify({ status: "setup_needed" }) + "\n");
    return;
  }
  if (
    readiness.code === 1 &&
    exactKeys(state, ["status", "reason"]) &&
    state.status === "not_ready" &&
    ["remote_session_rejected", "remote_status_unavailable"].includes(
      state.reason,
    )
  ) {
    process.stdout.write(
      JSON.stringify({ status: "not_ready", reason: state.reason }) + "\n",
    );
    return;
  }
  if (
    readiness.code === 1 &&
    exactKeys(state, ["status"]) &&
    state.status === "invalid_local_session"
  ) {
    process.stdout.write(
      JSON.stringify({ status: "invalid_local_session" }) + "\n",
    );
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

  const lookup = await invokeCli([
    "secrets",
    "find",
    "--alias",
    alias,
    ...(optional === "1" ? ["--optional"] : []),
  ]);
  if (lookup.code !== 0)
    throw new Error("AgentSecret reference lookup failed.");
  const receipt = lookup.result;
  if (optional === "1" && receipt?.status === "optional_not_found") {
    process.stdout.write(JSON.stringify({ status: receipt.status }) + "\n");
    return;
  }
  if (
    !receipt ||
    receipt.status !== "available" ||
    typeof receipt.reference !== "string"
  )
    throw new Error("AgentSecret returned an invalid reference receipt.");

  // Pass only a reference to the caller. The CLI never returns a credential value.
  process.stdout.write(
    JSON.stringify({ status: receipt.status, reference: receipt.reference }) +
      "\n",
  );
}

main().catch((error) => {
  process.stderr.write(
    (error instanceof Error
      ? error.message
      : "AgentSecret reference lookup failed.") + "\n",
  );
  process.exitCode = 1;
});
