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
  let processResult: ReturnType<typeof Bun.spawnSync>;
  try {
    processResult = Bun.spawnSync([nodeExecutable, cliPath, ...args], {
      env: { ...process.env },
    });
  } catch {
    throw new Error("AgentSecret companion could not be started.");
  }
  if (
    processResult.stdout.length > 64 * 1024 ||
    processResult.stderr.length > 16 * 1024
  )
    throw new Error("AgentSecret returned oversized output.");
  let result: unknown;
  try {
    result = JSON.parse(processResult.stdout.toString("utf8"));
  } catch {
    throw new Error("AgentSecret returned an invalid result.");
  }
  return { code: processResult.exitCode, result };
}

function emit(value: Record<string, string>) {
  process.stdout.write(JSON.stringify(value) + "\n");
}

function main() {
  const alias = Bun.env.AGENTSECRET_ALIAS;
  const reference = Bun.env.AGENTSECRET_REFERENCE;
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

  const { code, result } = invokeCli([
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
    typeof result.status === "string" &&
    (result.status === "unchanged" || result.status === "updated") &&
    result.reference === reference &&
    result.verified === true
  ) {
    emit({ status: result.status, reference: reference });
    return;
  }
  throw new Error("AgentSecret returned an invalid owner-ensure result.");
}

try {
  main();
} catch (error) {
  const safeMessages = new Set([
    "AgentSecret companion could not be started.",
    "AgentSecret returned oversized output.",
    "AgentSecret returned an invalid result.",
    "Set AGENTSECRET_ALIAS to an owner-approved alias.",
    "Set AGENTSECRET_REFERENCE to an exact owner-approved ref.",
    "AgentSecret returned an invalid owner-ensure result.",
  ]);
  const message = error instanceof Error ? error.message : "";
  process.stderr.write(
    (safeMessages.has(message) ? message : "Owner ensure failed.") + "\n",
  );
  process.exitCode = 1;
}
