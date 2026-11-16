import { createServer, isIP } from "node:net";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { listenUdpWitness } from "./linux-egress-udp-probes.mjs";

const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
const internalIpv6Subnet = `fd${suffix.slice(0, 2)}:${suffix.slice(2, 6)}:${suffix.slice(6, 10)}::/64`;
const externalIpv6Subnet = `fd${suffix.slice(10, 12)}:${suffix.slice(12, 16)}:${suffix.slice(6, 10)}::/64`;
const internalIpv6Gateway = internalIpv6Subnet.replace(/::\/64$/, "::1");
const externalIpv6Gateway = externalIpv6Subnet.replace(/::\/64$/, "::1");
const image = `agentsecret-linux-egress-acceptance:${suffix}`;
const internalNetwork = `agentsecret-egress-internal-${suffix}`;
const externalNetwork = `agentsecret-egress-external-${suffix}`;
const fixture = `agentsecret-egress-origin-${suffix}`;
const supervisor = `agentsecret-egress-supervisor-${suffix}`;
const guestConfig = `agentsecret-egress-inspect-${suffix}`;
const guestHardeningArgs = [
  "--read-only",
  "--cap-drop",
  "ALL",
  "--security-opt",
  "no-new-privileges",
];
const hostSecret = `synthetic-egress-secret-${randomUUID()}`;
const runCapability = randomUUID();
const brokerValues = {
  url: process.env.AGENTSECRET_EGRESS_BROKER_URL,
  capability: process.env.AGENTSECRET_EGRESS_BROKER_CAPABILITY,
  alias: process.env.AGENTSECRET_EGRESS_BROKER_ALIAS,
  requestUrl: process.env.AGENTSECRET_EGRESS_BROKER_REQUEST_URL,
};
const brokerConfigured = Object.values(brokerValues).some(
  (value) => value !== undefined,
);
let broker;
if (brokerConfigured) {
  if (
    Object.values(brokerValues).some((value) => !value) ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(brokerValues.alias) ||
    !/^aspc1\.[A-Za-z0-9_-]{1,80}\.[A-Za-z0-9_-]{43}$/.test(
      brokerValues.capability,
    )
  )
    throw new Error("invalid_broker_acceptance_configuration");
  const brokerUrl = new URL(brokerValues.url);
  const requestUrl = new URL(brokerValues.requestUrl);
  if (
    !["http:", "https:"].includes(brokerUrl.protocol) ||
    brokerUrl.username ||
    brokerUrl.password ||
    brokerUrl.pathname !== "/" ||
    brokerUrl.search ||
    brokerUrl.hash ||
    (brokerUrl.protocol !== "https:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(brokerUrl.hostname)) ||
    requestUrl.protocol !== "https:" ||
    requestUrl.username ||
    requestUrl.password ||
    requestUrl.hash ||
    (requestUrl.port && requestUrl.port !== "443")
  )
    throw new Error("invalid_broker_acceptance_configuration");
  broker = {
    url: brokerUrl.toString(),
    capability: brokerValues.capability,
    alias: brokerValues.alias,
    requestUrl: requestUrl.toString(),
  };
}
const dockerCommandTimeoutMs = Number(
  process.env.AGENTSECRET_DOCKER_COMMAND_TIMEOUT_MS ?? 300_000,
);
if (
  !Number.isSafeInteger(dockerCommandTimeoutMs) ||
  dockerCommandTimeoutMs < 100 ||
  dockerCommandTimeoutMs > 900_000
)
  throw new Error("invalid_docker_command_timeout");
const dockerOutputLimitBytes = 16 * 1024 * 1024;
const cleanupDeadlineMs = 15_000;
let cancellationSignal;
let cleanupStarted = false;
const activeDockerStops = new Set();
const cancelActiveDockerCommands = (signal) => {
  cancellationSignal ??= signal;
  for (const stop of activeDockerStops) stop();
};
process.on("SIGINT", () => cancelActiveDockerCommands("SIGINT"));
process.on("SIGTERM", () => cancelActiveDockerCommands("SIGTERM"));
let hostTrapHits = 0;
const hostTrapSockets = new Set();
let brokerEnvDirectory;
let brokerEnvFile;
function ipv4Range(cidr) {
  const [address, prefixText] = cidr.split("/");
  const prefix = Number(prefixText);
  if (
    isIP(address) !== 4 ||
    !Number.isInteger(prefix) ||
    prefix < 0 ||
    prefix > 32
  )
    return undefined;
  const value = address
    .split(".")
    .reduce((result, octet) => result * 256 + Number(octet), 0);
  const size = 2 ** (32 - prefix);
  const start = Math.floor(value / size) * size;
  return [start, start + size - 1];
}
function ipv4RangesOverlap(left, right) {
  return !!left && !!right && left[0] <= right[1] && right[0] <= left[1];
}
function gatewayForIpv4Subnet(subnet) {
  const [address, prefix] = subnet.split("/");
  if (prefix !== "24") throw new Error("invalid_acceptance_ipv4_subnet");
  const octets = address.split(".").map(Number);
  octets[3] += 1;
  return octets.join(".");
}
async function unusedIpv4Subnet(pool, startAt, usedRanges) {
  for (let offset = 0; offset < 256; offset += 1) {
    const thirdOctet = (startAt + offset) % 256;
    const candidate = `${pool}.${thirdOctet}.0/24`;
    const range = ipv4Range(candidate);
    if (usedRanges.every((used) => !ipv4RangesOverlap(range, used))) {
      usedRanges.push(range);
      return candidate;
    }
  }
  throw new Error("acceptance_ipv4_subnet_pool_exhausted");
}
async function selectIpv4Subnets() {
  const ids = (await run(["network", "ls", "--quiet"]))
    .split(/\s+/)
    .filter(Boolean);
  const networks = ids.length
    ? JSON.parse(await run(["network", "inspect", ...ids]))
    : [];
  if (!Array.isArray(networks))
    throw new Error("invalid_docker_network_inventory");
  const usedRanges = [];
  for (const network of networks) {
    const configs = network?.IPAM?.Config;
    if (!Array.isArray(configs)) continue;
    for (const config of configs) {
      if (typeof config?.Subnet !== "string") continue;
      const range = ipv4Range(config.Subnet);
      if (range) usedRanges.push(range);
    }
  }
  const start = Number.parseInt(suffix.slice(0, 2), 16);
  const internal = await unusedIpv4Subnet("198.19", start, usedRanges);
  const external = await unusedIpv4Subnet(
    "198.18",
    Number.parseInt(suffix.slice(2, 4), 16),
    usedRanges,
  );
  return { internal, external };
}
const hostTrap = createServer((socket) => {
  hostTrapHits++;
  hostTrapSockets.add(socket);
  socket.once("close", () => hostTrapSockets.delete(socket));
  socket.end(
    "HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\nhost-admin-reached",
  );
});
const run = (
  args,
  timeoutMs = dockerCommandTimeoutMs,
  allowDuringCancellation = false,
) =>
  new Promise((resolve, reject) => {
    if (cancellationSignal && !allowDuringCancellation) {
      reject(new Error(`docker_probe_cancelled:${cancellationSignal}`));
      return;
    }
    const child = spawn("docker", args, {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let outputLimitExceeded = false;
    let timedOut = false;
    let escalationTimer;
    let stopping = false;
    const terminateGroup = (signal) => {
      if (child.pid === undefined) return;
      try {
        process.kill(-child.pid, signal);
      } catch {}
      try {
        child.kill(signal);
      } catch {}
    };
    const stopGroup = () => {
      if (stopping) return;
      stopping = true;
      terminateGroup("SIGTERM");
      escalationTimer = setTimeout(() => terminateGroup("SIGKILL"), 1000);
    };
    activeDockerStops.add(stopGroup);
    const append = (target, chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > dockerOutputLimitBytes) {
        outputLimitExceeded = true;
        stopGroup();
        return;
      }
      target.push(chunk);
    };
    child.stdout.on("data", (chunk) => append(stdout, chunk));
    child.stderr.on("data", (chunk) => append(stderr, chunk));
    const timeout = setTimeout(() => {
      timedOut = true;
      stopGroup();
    }, timeoutMs);
    child.once("error", (error) => {
      activeDockerStops.delete(stopGroup);
      clearTimeout(timeout);
      clearTimeout(escalationTimer);
      reject(error);
    });
    child.once("close", (code) => {
      activeDockerStops.delete(stopGroup);
      clearTimeout(timeout);
      clearTimeout(escalationTimer);
      const errorText = Buffer.concat(stderr).toString("utf8").trim();
      if (cancellationSignal && !allowDuringCancellation) {
        reject(new Error(`docker_probe_cancelled:${cancellationSignal}`));
      } else if (timedOut) {
        reject(new Error(`docker_command_timed_out:${args[0] || "unknown"}`));
      } else if (outputLimitExceeded) {
        reject(
          new Error(`docker_output_limit_exceeded:${args[0] || "unknown"}`),
        );
      } else if (code !== 0) {
        reject(
          new Error(
            errorText || `docker_command_failed:${args[0] || "unknown"}`,
          ),
        );
      } else {
        resolve(Buffer.concat(stdout).toString("utf8").trim());
      }
    });
  });

await new Promise((resolve, reject) => {
  hostTrap.once("error", reject);
  hostTrap.listen({ host: "::", port: 0, ipv6Only: false }, resolve);
});
const hostTrapPort = hostTrap.address().port;
let hostUdpWitness;
try {
  hostUdpWitness = await listenUdpWitness(hostTrapPort, () => hostTrapHits++);
} catch (error) {
  await new Promise((resolve) => {
    hostTrap.close(resolve);
    for (const socket of hostTrapSockets) socket.destroy();
  });
  throw error;
}

try {
  const ipv4Subnets = await selectIpv4Subnets();
  const internalIpv4Gateway = gatewayForIpv4Subnet(ipv4Subnets.internal);
  const externalIpv4Gateway = gatewayForIpv4Subnet(ipv4Subnets.external);
  await run([
    "build",
    "--quiet",
    "--file",
    "scripts/linux-egress-boundary.Dockerfile",
    "--tag",
    image,
    ".",
  ]);
  await run([
    "network",
    "create",
    "--internal",
    "--driver",
    "bridge",
    "--ipv6",
    "--subnet",
    ipv4Subnets.internal,
    "--gateway",
    internalIpv4Gateway,
    "--subnet",
    internalIpv6Subnet,
    "--gateway",
    internalIpv6Gateway,
    internalNetwork,
  ]);
  await run([
    "network",
    "create",
    "--driver",
    "bridge",
    "--ipv6",
    "--subnet",
    ipv4Subnets.external,
    "--gateway",
    externalIpv4Gateway,
    "--subnet",
    externalIpv6Subnet,
    "--gateway",
    externalIpv6Gateway,
    externalNetwork,
  ]);
  await run([
    "run",
    "--detach",
    "--rm",
    "--name",
    fixture,
    "--network",
    externalNetwork,
    "--network-alias",
    "origin",
    "--env",
    `EXPECTED_SECRET=${hostSecret}`,
    image,
    "node",
    "/opt/linux-egress-fixture.mjs",
  ]);
  const supervisorArgs = [
    "run",
    "--detach",
    "--rm",
    "--name",
    supervisor,
    "--network",
    externalNetwork,
  ];
  if (broker) {
    const scratchRoot = join(process.cwd(), "tmp");
    await mkdir(scratchRoot, { recursive: true });
    brokerEnvDirectory = await mkdtemp(
      join(scratchRoot, "agentsecret-egress-broker-"),
    );
    brokerEnvFile = join(brokerEnvDirectory, "supervisor.env");
    await writeFile(
      brokerEnvFile,
      [
        `BROKER_URL=${broker.url}`,
        `BROKER_CAPABILITY=${broker.capability}`,
        `BROKER_ALIAS=${broker.alias}`,
        `UPSTREAM_BODY_URL=${broker.requestUrl}`,
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    await chmod(brokerEnvFile, 0o600);
    supervisorArgs.push("--env-file", brokerEnvFile);
  } else {
    supervisorArgs.push("--env", `SYNTHETIC_SECRET=${hostSecret}`);
  }
  supervisorArgs.push(
    "--env",
    `RUN_CAPABILITY=${runCapability}`,
    image,
    "node",
    "/opt/linux-egress-supervisor.mjs",
  );
  await run(supervisorArgs);
  if (brokerEnvDirectory) {
    await rm(brokerEnvDirectory, { recursive: true, force: true });
    brokerEnvDirectory = undefined;
    brokerEnvFile = undefined;
  }
  await run([
    "network",
    "connect",
    "--alias",
    "supervisor",
    internalNetwork,
    supervisor,
  ]);

  const internalNetworkConfig = JSON.parse(
    await run([
      "network",
      "inspect",
      "--format",
      "{{json .IPAM.Config}}",
      internalNetwork,
    ]),
  );
  const internalGateways = internalNetworkConfig
    .map((entry) => entry?.Gateway)
    .filter((gateway) => typeof gateway === "string");
  const internalGatewayIp = internalGateways.find(
    (gateway) => isIP(gateway) === 4,
  );
  const internalGatewayIpv6 = internalGateways.find(
    (gateway) => isIP(gateway) === 6,
  );
  if (!internalGatewayIp || !internalGatewayIpv6)
    throw new Error("internal_network_gateway_missing");

  const originNetworks = JSON.parse(
    await run([
      "inspect",
      "--format",
      "{{json .NetworkSettings.Networks}}",
      fixture,
    ]),
  );
  const supervisorNetworks = JSON.parse(
    await run([
      "inspect",
      "--format",
      "{{json .NetworkSettings.Networks}}",
      supervisor,
    ]),
  );
  const originExternalIp = originNetworks[externalNetwork]?.IPAddress;
  const supervisorExternalIp = supervisorNetworks[externalNetwork]?.IPAddress;
  const originExternalIpv6 = originNetworks[externalNetwork]?.GlobalIPv6Address;
  const supervisorExternalIpv6 =
    supervisorNetworks[externalNetwork]?.GlobalIPv6Address;
  if (
    !originExternalIp ||
    !supervisorExternalIp ||
    isIP(originExternalIpv6) !== 6 ||
    isIP(supervisorExternalIpv6) !== 6
  )
    throw new Error("docker_network_address_missing");

  await delay(500);
  const acceptance = await run([
    "run",
    "--rm",
    "--network",
    internalNetwork,
    ...guestHardeningArgs,
    "--add-host",
    `override.example.test:${supervisorExternalIp}`,
    "--env",
    `HOST_TRAP_PORT=${hostTrapPort}`,
    "--env",
    `INTERNAL_GATEWAY_IP=${internalGatewayIp}`,
    "--env",
    `INTERNAL_GATEWAY_IPV6=${internalGatewayIpv6}`,
    "--env",
    `RUN_CAPABILITY=${runCapability}`,
    "--env",
    `SUPERVISOR_EXTERNAL_IP=${supervisorExternalIp}`,
    "--env",
    `ORIGIN_EXTERNAL_IP=${originExternalIp}`,
    "--env",
    `SUPERVISOR_EXTERNAL_IPV6=${supervisorExternalIpv6}`,
    "--env",
    `ORIGIN_EXTERNAL_IPV6=${originExternalIpv6}`,
    "--env",
    "BODY_PLACEHOLDER={{AGENTSECRET_SECRET}}",
    "--env",
    `REQUEST_ALIAS=${broker?.alias ?? "fixture"}`,
    "--env",
    `REQUEST_BODY_URL=${broker?.requestUrl ?? "http://origin:8081/body-check"}`,
    ...(broker ? ["--env", "BROKER_MODE=1"] : []),
    image,
    "node",
    "/opt/linux-egress-guest.mjs",
  ]);
  for (const container of [supervisor, fixture]) {
    const logs = await run(["logs", container]);
    if (logs.includes("udp_witness_hit"))
      throw new Error("udp_witness_reachable");
    if (logs.includes("udp_witness_error"))
      throw new Error("udp_witness_unavailable");
  }
  if (hostUdpWitness.errors.length !== 0)
    throw new Error("host_udp_witness_unavailable");
  if (hostTrapHits !== 0) throw new Error("host_trap_reachable");
  console.log(acceptance);

  await run([
    "run",
    "--detach",
    "--name",
    guestConfig,
    "--network",
    internalNetwork,
    ...guestHardeningArgs,
    image,
    "node",
    "-e",
    "setTimeout(() => {}, 60000)",
  ]);
  try {
    const mounts = JSON.parse(
      await run(["inspect", "--format", "{{json .Mounts}}", guestConfig]),
    );
    if (mounts.length !== 0) throw new Error("guest_has_shared_mounts");
    const hostConfig = JSON.parse(
      await run(["inspect", "--format", "{{json .HostConfig}}", guestConfig]),
    );
    const configuredUser = await run([
      "inspect",
      "--format",
      "{{.Config.User}}",
      guestConfig,
    ]);
    if (
      configuredUser !== "node" ||
      hostConfig.Privileged !== false ||
      hostConfig.ReadonlyRootfs !== true ||
      (hostConfig.CapAdd ?? []).length !== 0 ||
      !(hostConfig.CapDrop ?? []).includes("ALL") ||
      (hostConfig.Devices ?? []).length !== 0 ||
      (hostConfig.Binds ?? []).length !== 0 ||
      !(hostConfig.SecurityOpt ?? []).some((value) =>
        value.startsWith("no-new-privileges"),
      )
    )
      throw new Error("guest_container_not_hardened");
    const networks = JSON.parse(
      await run([
        "inspect",
        "--format",
        "{{json .NetworkSettings.Networks}}",
        guestConfig,
      ]),
    );
    if (
      Object.keys(networks).length !== 1 ||
      !Object.hasOwn(networks, internalNetwork)
    )
      throw new Error("guest_has_untrusted_network");
  } finally {
    try {
      await run(["stop", guestConfig]);
    } catch {}
  }
} catch (error) {
  if (!cancellationSignal) throw error;
  console.error(`docker_probe_cancelled:${cancellationSignal}`);
  process.exitCode = cancellationSignal === "SIGINT" ? 130 : 143;
} finally {
  cleanupStarted = true;
  const cleanupDeadline = Date.now() + cleanupDeadlineMs;
  const cleanupRun = async (args) => {
    const remainingMs = cleanupDeadline - Date.now();
    if (remainingMs <= 0) return;
    await run(
      args,
      Math.min(dockerCommandTimeoutMs, remainingMs),
      cleanupStarted,
    );
  };
  for (const container of [supervisor, fixture]) {
    try {
      await cleanupRun(["rm", "--force", container]);
    } catch {}
  }
  try {
    await cleanupRun(["rm", "--force", guestConfig]);
  } catch {}
  for (const network of [internalNetwork, externalNetwork]) {
    try {
      await cleanupRun(["network", "rm", network]);
    } catch {}
  }
  try {
    await cleanupRun(["image", "rm", image]);
  } catch {}
  await hostUdpWitness.close();
  await new Promise((resolve) => {
    hostTrap.close(resolve);
    for (const socket of hostTrapSockets) socket.destroy();
  });
  if (brokerEnvDirectory) {
    await rm(brokerEnvDirectory, { recursive: true, force: true });
  }
}
if (cancellationSignal)
  process.exitCode = cancellationSignal === "SIGINT" ? 130 : 143;
