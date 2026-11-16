import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const cliPath = fileURLToPath(
  new URL("../../../dist/cli.mjs", import.meta.url),
);

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === [...keys].sort().join(",")
  );
}

function invokeCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      env: { ...process.env },
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

function emit(value) {
  process.stdout.write(JSON.stringify(value) + "\n");
}

async function main() {
  const alias = process.env.AGENTSECRET_ALIAS;
  const reference = process.env.AGENTSECRET_REFERENCE;
  if (!alias || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias))
    throw new Error("Set AGENTSECRET_ALIAS to an owner-approved alias.");
  if (
    !reference ||
    reference !== reference.trim() ||
    reference.length > 1024 ||
    /[\u0000-\u001f\u007f]/.test(reference)
  )
    throw new Error(
      "Set AGENTSECRET_REFERENCE to an exact owner-approved ref.",
    );

  const { code, result } = await invokeCli([
    "secrets",
    "ensure",
    "--alias",
    alias,
    "--reference",
    reference,
  ]);
  if (
    exactKeys(result, ["status", "requestId"]) &&
    typeof result.requestId === "string" &&
    /^[A-Za-z0-9_-]{20,128}$/.test(result.requestId)
  ) {
    if (result.status === "owner_input_required" && code === 0) {
      emit({ status: result.status, requestId: result.requestId });
      return;
    }
    if (result.status === "outcome_unknown" && code === 1) {
      emit({ status: result.status, requestId: result.requestId });
      process.exitCode = 1;
      return;
    }
  }
  if (
    code === 0 &&
    exactKeys(result, ["status", "reference", "verified"]) &&
    ["unchanged", "updated"].includes(result.status) &&
    result.reference === reference &&
    result.verified === true
  ) {
    emit({ status: result.status, reference: result.reference });
    return;
  }
  throw new Error("AgentSecret returned an invalid owner-ensure result.");
}

main().catch((error) => {
  process.stderr.write(
    (error instanceof Error ? error.message : "Owner ensure failed.") + "\n",
  );
  process.exitCode = 1;
});
