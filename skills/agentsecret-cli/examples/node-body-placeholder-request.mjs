import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const cliPath = fileURLToPath(
  new URL("../../../dist/cli.mjs", import.meta.url),
);
function invokeCli(args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
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
      if (stdoutBytes > 640 * 1024) {
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
      if (code !== 0) {
        reject(new Error("AgentSecret request failed."));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(stdout).toString("utf8")));
      } catch {
        reject(new Error("AgentSecret returned an invalid JSON result."));
      }
    });
    child.stdin.end(input);
  });
}

async function main() {
  const alias = process.env.AGENTSECRET_ALIAS;
  const destinationText = process.env.AGENTSECRET_URL;
  if (!alias || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias))
    throw new Error("Set AGENTSECRET_ALIAS to an owner-approved alias.");
  if (!destinationText)
    throw new Error("Set AGENTSECRET_URL to an owner-approved HTTPS endpoint.");

  let destination;
  try {
    destination = new URL(destinationText);
  } catch {
    throw new Error("AGENTSECRET_URL must be a public HTTPS endpoint.");
  }
  if (
    destination.protocol !== "https:" ||
    destination.username ||
    destination.password ||
    destination.search ||
    destination.hash ||
    (destination.port && destination.port !== "443")
  )
    throw new Error("AGENTSECRET_URL must be a public HTTPS endpoint.");

  const requestInput = JSON.stringify({
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ credential: "{{AGENTSECRET_SECRET}}" }),
  });
  const response = await invokeCli(
    [
      "request",
      "--alias",
      alias,
      "--url",
      destination.href,
      "--method",
      "POST",
      "--stdin",
    ],
    requestInput,
  );
  if (!Number.isInteger(response?.status) || response.status < 100)
    throw new Error("AgentSecret returned an invalid request result.");

  // Do not forward arbitrary upstream response bodies into the calling app's logs.
  process.stdout.write(
    JSON.stringify({ status: "completed", upstream_status: response.status }) +
      "\n",
  );
}

main().catch((error) => {
  process.stderr.write(
    (error instanceof Error ? error.message : "AgentSecret request failed.") +
      "\n",
  );
  process.exitCode = 1;
});
