import assert from "node:assert/strict";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  assertTcpUnreachable,
  tcpBypassTargets,
} from "../scripts/linux-egress-tcp-probes.mjs";
import {
  assertUdpUnreachable,
  listenUdpWitness,
  udpBypassTargets,
} from "../scripts/linux-egress-udp-probes.mjs";

const root = new URL("../", import.meta.url).pathname;

test("Linux egress TCP probe targets every fixture and host route", () => {
  assert.deepEqual(
    tcpBypassTargets({
      SUPERVISOR_EXTERNAL_IP: "203.0.113.10",
      SUPERVISOR_EXTERNAL_IPV6: "2001:db8::10",
      ORIGIN_EXTERNAL_IP: "203.0.113.11",
      ORIGIN_EXTERNAL_IPV6: "2001:db8::11",
      INTERNAL_GATEWAY_IP: "172.30.0.1",
      INTERNAL_GATEWAY_IPV6: "fd00:1234:5678::1",
      HOST_TRAP_PORT: "34678",
    }),
    [
      {
        label: "raw_tcp_supervisor_ipv4_bypass",
        host: "203.0.113.10",
        port: 8080,
      },
      {
        label: "raw_tcp_supervisor_ipv6_bypass",
        host: "2001:db8::10",
        port: 8080,
      },
      {
        label: "raw_tcp_origin_ipv4_bypass",
        host: "203.0.113.11",
        port: 8081,
      },
      {
        label: "raw_tcp_origin_ipv6_bypass",
        host: "2001:db8::11",
        port: 8081,
      },
      {
        label: "raw_tcp_host_service_bypass",
        host: "host.docker.internal",
        port: 34678,
      },
      {
        label: "raw_tcp_host_gateway_ipv4_bypass",
        host: "172.30.0.1",
        port: 34678,
      },
      {
        label: "raw_tcp_host_gateway_ipv6_bypass",
        host: "fd00:1234:5678::1",
        port: 34678,
      },
    ],
  );
});

test("Linux egress TCP probe refuses incomplete network state", () => {
  assert.throws(() => tcpBypassTargets({}), /invalid_tcp_bypass_target/);
});

test("Linux egress TCP probe fails when a fixture listener is reachable", async (t) => {
  const server = createServer((socket) => socket.end());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  await assert.rejects(
    assertTcpUnreachable("fixture_raw_tcp", "127.0.0.1", port),
    /fixture_raw_tcp_reachable/,
  );
});

test("Linux egress UDP probe targets IPv4 and IPv6 fixture and host routes", () => {
  assert.deepEqual(
    udpBypassTargets({
      SUPERVISOR_EXTERNAL_IP: "203.0.113.10",
      SUPERVISOR_EXTERNAL_IPV6: "2001:db8::10",
      ORIGIN_EXTERNAL_IP: "203.0.113.11",
      ORIGIN_EXTERNAL_IPV6: "2001:db8::11",
      INTERNAL_GATEWAY_IP: "172.30.0.1",
      INTERNAL_GATEWAY_IPV6: "fd00:1234:5678::1",
      HOST_TRAP_PORT: "34678",
    }),
    [
      {
        label: "raw_udp_supervisor_ipv4_bypass",
        host: "203.0.113.10",
        port: 8082,
        type: "udp4",
      },
      {
        label: "raw_udp_supervisor_ipv6_bypass",
        host: "2001:db8::10",
        port: 8082,
        type: "udp6",
      },
      {
        label: "raw_udp_origin_ipv4_bypass",
        host: "203.0.113.11",
        port: 8082,
        type: "udp4",
      },
      {
        label: "raw_udp_origin_ipv6_bypass",
        host: "2001:db8::11",
        port: 8082,
        type: "udp6",
      },
      {
        label: "raw_udp_host_service_bypass",
        host: "host.docker.internal",
        port: 34678,
        type: "udp4",
      },
      {
        label: "raw_udp_host_gateway_ipv4_bypass",
        host: "172.30.0.1",
        port: 34678,
        type: "udp4",
      },
      {
        label: "raw_udp_host_gateway_ipv6_bypass",
        host: "fd00:1234:5678::1",
        port: 34678,
        type: "udp6",
      },
    ],
  );
});

test("Linux egress UDP probe fails when an IPv4 or IPv6 fixture listener is reachable", async (t) => {
  const witness = await listenUdpWitness(0);
  t.after(() => witness.close());
  for (const [host, type] of [
    ["127.0.0.1", "udp4"],
    ["::1", "udp6"],
  ]) {
    await assert.rejects(
      assertUdpUnreachable(`fixture_raw_${type}`, host, witness.port, type),
      new RegExp(`fixture_raw_${type}_reachable`),
    );
  }
});

function withTimeout(promise, timeoutMs, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

async function waitForFile(file, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await readFile(file);
      return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.fail(`timed out waiting for ${path.basename(file)}`);
}

async function runWithBrokerConfig(t, brokerConfig) {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), "agentsecret-egress-broker-config-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const dockerCallsFile = path.join(directory, "docker-called");
  const docker = path.join(directory, "docker");
  const dockerStub =
    '#!/usr/bin/env node\nrequire("node:fs").writeFileSync(' +
    JSON.stringify(dockerCallsFile) +
    ', "called");\n';
  await writeFile(docker, dockerStub);
  await chmod(docker, 0o755);
  const env = {
    ...process.env,
    PATH: `${directory}${path.delimiter}${process.env.PATH ?? ""}`,
    AGENTSECRET_DOCKER_COMMAND_TIMEOUT_MS: "1000",
  };
  for (const name of [
    "AGENTSECRET_EGRESS_BROKER_URL",
    "AGENTSECRET_EGRESS_BROKER_CAPABILITY",
    "AGENTSECRET_EGRESS_BROKER_ALIAS",
    "AGENTSECRET_EGRESS_BROKER_REQUEST_URL",
  ])
    delete env[name];
  Object.assign(env, brokerConfig);

  const child = spawn(
    process.execPath,
    [path.join(root, "scripts/accept-linux-egress-boundary.mjs")],
    { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] },
  );
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
  const result = await new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  return { result, stderr, dockerCallsFile };
}

function assertGuestRunHardening(dockerCalls, { broker } = {}) {
  const guestRun = dockerCalls.find(
    (args) => args[0] === "run" && args.includes("/opt/linux-egress-guest.mjs"),
  );
  assert.ok(guestRun, "probe launched the synthetic guest");
  assert.ok(guestRun.includes("--read-only"));
  assert.ok(
    guestRun.some(
      (value, index) => value === "--cap-drop" && guestRun[index + 1] === "ALL",
    ),
  );
  assert.ok(
    guestRun.some(
      (value, index) =>
        value === "--security-opt" &&
        guestRun[index + 1] === "no-new-privileges",
    ),
  );
  const valueOptions = new Set([
    "--add-host",
    "--cap-add",
    "--cap-drop",
    "--cgroupns",
    "--cpus",
    "--device",
    "--device-cgroup-rule",
    "--dns",
    "--entrypoint",
    "--env",
    "--env-file",
    "--expose",
    "--gpus",
    "--hostname",
    "--ipc",
    "--label",
    "--memory",
    "--mount",
    "--name",
    "--net",
    "--network",
    "--pid",
    "--pids-limit",
    "--platform",
    "--publish",
    "--pull",
    "--restart",
    "--security-opt",
    "--shm-size",
    "--stop-signal",
    "--stop-timeout",
    "--ulimit",
    "--user",
    "--userns",
    "--uts",
    "--volume",
    "--volumes-from",
    "--workdir",
    "-e",
    "-l",
    "-p",
    "-v",
  ]);
  const flagOptions = new Set([
    "--init",
    "--interactive",
    "--privileged",
    "--publish-all",
    "--read-only",
    "--rm",
    "--sig-proxy",
    "--tty",
    "-i",
    "-P",
    "-t",
  ]);
  const parsedOptions = [];
  let imageIndex = -1;
  for (let index = 1; index < guestRun.length; index += 1) {
    const token = guestRun[index];
    if (token === "--") {
      imageIndex = index + 1;
      break;
    }
    if (!token.startsWith("-") || token === "-") {
      imageIndex = index;
      break;
    }
    if (token.startsWith("--")) {
      const separator = token.indexOf("=");
      const name = separator === -1 ? token : token.slice(0, separator);
      assert.ok(
        valueOptions.has(name) || flagOptions.has(name),
        `guest launch uses a recognized Docker option (${name})`,
      );
      let value;
      if (valueOptions.has(name)) {
        if (separator !== -1) value = token.slice(separator + 1);
        else {
          assert.ok(index + 1 < guestRun.length, `${name} has a value`);
          value = guestRun[++index];
        }
      } else {
        assert.equal(separator, -1, `${name} is a flag`);
      }
      parsedOptions.push({ name, value });
      continue;
    }
    const shortOptions = token.slice(1);
    for (let offset = 0; offset < shortOptions.length; offset += 1) {
      const name = `-${shortOptions[offset]}`;
      assert.ok(
        valueOptions.has(name) || flagOptions.has(name),
        `guest launch uses a recognized Docker option (${name})`,
      );
      if (valueOptions.has(name)) {
        const attachedValue = shortOptions.slice(offset + 1).replace(/^=/, "");
        let value = attachedValue;
        if (!value) {
          assert.ok(index + 1 < guestRun.length, `${name} has a value`);
          value = guestRun[++index];
        }
        parsedOptions.push({ name, value });
        break;
      }
      parsedOptions.push({ name });
    }
  }
  assert.ok(imageIndex > 1, "guest launch has an image after Docker options");
  assert.ok(
    guestRun.slice(imageIndex + 1).includes("/opt/linux-egress-guest.mjs"),
    "guest script follows its image and command",
  );
  const optionValues = (names) =>
    parsedOptions
      .filter(({ name }) => names.includes(name))
      .map(({ value }) => value);
  const internalNetwork = dockerCalls.find(
    (args) =>
      args[0] === "network" &&
      args[1] === "create" &&
      args.includes("--internal"),
  );
  assert.ok(internalNetwork);
  assert.deepEqual(optionValues(["--network", "--net"]), [
    internalNetwork.at(-1),
  ]);
  for (const option of ["--mount", "--volume", "-v", "--volumes-from"])
    assert.deepEqual(
      optionValues([option]),
      [],
      `guest launch excludes ${option}`,
    );
  for (const option of ["--device", "--device-cgroup-rule", "--gpus"])
    assert.deepEqual(
      optionValues([option]),
      [],
      `guest launch excludes ${option}`,
    );
  for (const option of [
    "--privileged",
    "--cap-add",
    "--publish",
    "--publish-all",
    "-p",
    "-P",
  ])
    assert.deepEqual(
      optionValues([option]),
      [],
      `guest launch excludes ${option}`,
    );
  for (const option of ["--pid", "--ipc", "--uts", "--userns", "--cgroupns"])
    assert.ok(
      optionValues([option]).every((value) => value !== "host"),
      `guest launch does not use host ${option.slice(2)} namespace`,
    );
  assert.ok(
    optionValues(["--security-opt"]).every(
      (value) => !/^(?:seccomp|apparmor)[:=]unconfined$/i.test(value),
    ),
    "guest launch uses no unconfined security options",
  );
  assert.deepEqual(
    optionValues(["--env-file"]),
    [],
    "guest launch receives no indirect environment-file values",
  );

  const supervisorRun = dockerCalls.find(
    (args) =>
      args[0] === "run" && args.includes("/opt/linux-egress-supervisor.mjs"),
  );
  const fixtureRun = dockerCalls.find(
    (args) =>
      args[0] === "run" && args.includes("/opt/linux-egress-fixture.mjs"),
  );
  const supervisorSecret = supervisorRun?.find((value) =>
    value.startsWith("SYNTHETIC_SECRET="),
  );
  const fixtureSecret = fixtureRun?.find((value) =>
    value.startsWith("EXPECTED_SECRET="),
  );
  assert.ok(fixtureSecret);
  if (broker) {
    assert.equal(supervisorSecret, undefined);
    assert.ok(supervisorRun?.includes("--env-file"));
    assert.ok(
      dockerCalls.every((args) =>
        args.every((argument) => !argument.includes(broker.capability)),
      ),
      "broker capability value is absent from Docker command arguments",
    );
    assert.ok(guestRun.includes(`REQUEST_ALIAS=${broker.alias}`));
    assert.ok(guestRun.includes(`REQUEST_BODY_URL=${broker.requestUrl}`));
    assert.ok(guestRun.includes("BROKER_MODE=1"));
    assert.ok(
      guestRun.every((argument) => !argument.includes(broker.capability)),
      "broker capability is absent from every guest launch argument",
    );
  } else {
    assert.ok(supervisorSecret);
  }
  for (const assignment of [supervisorSecret, fixtureSecret].filter(Boolean)) {
    assert.ok(assignment);
    const separator = assignment.indexOf("=");
    assert.ok(separator >= 0 && separator < assignment.length - 1);
    const secret = assignment.slice(separator + 1);
    assert.ok(
      guestRun.every((argument) => !argument.includes(secret)),
      "synthetic secret value is absent from every guest launch argument",
    );
  }
  assert.deepEqual(
    optionValues(["--env", "-e"]).filter(
      (value) =>
        value === "BODY_PLACEHOLDER" || value.startsWith("BODY_PLACEHOLDER="),
    ),
    ["BODY_PLACEHOLDER={{AGENTSECRET_SECRET}}"],
    "guest receives exactly one safe body placeholder assignment",
  );
}

test("fake Docker launch guard rejects unsafe spellings and secret values", () => {
  const secret = "synthetic-host-secret";
  const internalNetwork = [
    "network",
    "create",
    "--internal",
    "egress-internal",
  ];
  const supervisor = [
    "run",
    "--env",
    `SYNTHETIC_SECRET=${secret}`,
    "fixture-image",
    "node",
    "/opt/linux-egress-supervisor.mjs",
  ];
  const fixture = [
    "run",
    "--env",
    `EXPECTED_SECRET=${secret}`,
    "fixture-image",
    "node",
    "/opt/linux-egress-fixture.mjs",
  ];
  const guest = [
    "run",
    "--rm",
    "--network",
    "egress-internal",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--env",
    "BODY_PLACEHOLDER={{AGENTSECRET_SECRET}}",
    "fixture-image",
    "node",
    "/opt/linux-egress-guest.mjs",
  ];
  const calls = [internalNetwork, supervisor, fixture, guest];
  assert.doesNotThrow(() => assertGuestRunHardening(calls));

  const imageIndex = guest.indexOf("fixture-image");
  const withExtraOptions = (options) => [
    ...guest.slice(0, imageIndex),
    ...options,
    ...guest.slice(imageIndex),
  ];
  for (const options of [
    ["--network=external"],
    ["--env-file", "/tmp/guest.env"],
    ["--net", "host"],
    ["--mount=type=bind,source=/tmp,target=/shared"],
    ["--volume", "/tmp:/shared"],
    ["-v", "/tmp:/shared"],
    ["-v/tmp:/shared"],
    ["-iv/tmp:/shared"],
    ["--volumes-from=host-container"],
    ["--device=/dev/sda"],
    ["--gpus", "all"],
    ["--gpus=all"],
    ["--privileged=true"],
    ["--cap-add=SYS_ADMIN"],
    ["--publish=0.0.0.0:8080:8080"],
    ["-p", "8080:8080"],
    ["-p8080:8080"],
    ["-ip8080:8080"],
    ["--publish-all"],
    ["-P"],
    ["-iP"],
    ["--pid=host"],
    ["--ipc", "host"],
    ["--uts=host"],
    ["--userns=host"],
    ["--cgroupns", "host"],
  ]) {
    assert.throws(() =>
      assertGuestRunHardening([
        internalNetwork,
        supervisor,
        fixture,
        withExtraOptions(options),
      ]),
    );
  }

  for (const securityValue of [
    "seccomp=unconfined",
    "seccomp:unconfined",
    "apparmor=unconfined",
    "apparmor:unconfined",
  ]) {
    for (const option of [
      ["--security-opt", securityValue],
      [`--security-opt=${securityValue}`],
    ]) {
      assert.throws(() =>
        assertGuestRunHardening([
          internalNetwork,
          supervisor,
          fixture,
          withExtraOptions(option),
        ]),
      );
    }
  }

  for (const leak of [["--env", `LEAK=${secret}`], [`prefix-${secret}`]]) {
    assert.throws(() =>
      assertGuestRunHardening([
        internalNetwork,
        supervisor,
        fixture,
        withExtraOptions(leak),
      ]),
    );
  }

  for (const override of [
    ["--env", "BODY_PLACEHOLDER=wrong"],
    ["--env=BODY_PLACEHOLDER=wrong"],
    ["-eBODY_PLACEHOLDER=wrong"],
    ["--env", "BODY_PLACEHOLDER"],
    ["--env=BODY_PLACEHOLDER"],
    ["-eBODY_PLACEHOLDER"],
  ]) {
    assert.throws(() =>
      assertGuestRunHardening([
        internalNetwork,
        supervisor,
        fixture,
        withExtraOptions(override),
      ]),
    );
  }

  assert.throws(() =>
    assertGuestRunHardening([
      internalNetwork,
      supervisor,
      fixture,
      withExtraOptions([
        "--label",
        "/opt/linux-egress-guest.mjs",
        "--privileged=true",
        "--pid=host",
        "-v/tmp:/shared",
        "-p8080:8080",
        "--security-opt=seccomp=unconfined",
      ]),
    ]),
  );

  const guestWithoutPlaceholder = guest.filter(
    (value, index, values) =>
      !(
        value === "--env" && values[index + 1]?.startsWith("BODY_PLACEHOLDER=")
      ) && !value.startsWith("BODY_PLACEHOLDER="),
  );
  assert.throws(() =>
    assertGuestRunHardening([
      internalNetwork,
      supervisor,
      fixture,
      [...guestWithoutPlaceholder, "BODY_PLACEHOLDER={{AGENTSECRET_SECRET}}"],
    ]),
  );
});

test("broker acceptance refuses partial or unsafe broker settings before Docker launch", async (t) => {
  const capability = `aspc1.default.${"C".repeat(43)}`;
  const requestUrl = "https://api.github.com/check";
  for (const brokerConfig of [
    {
      AGENTSECRET_EGRESS_BROKER_URL: "https://broker.example.test",
      AGENTSECRET_EGRESS_BROKER_CAPABILITY: capability,
    },
    {
      AGENTSECRET_EGRESS_BROKER_URL: "http://broker.example.test",
      AGENTSECRET_EGRESS_BROKER_CAPABILITY: capability,
      AGENTSECRET_EGRESS_BROKER_ALIAS: "TEST",
      AGENTSECRET_EGRESS_BROKER_REQUEST_URL: requestUrl,
    },
  ]) {
    const observed = await runWithBrokerConfig(t, brokerConfig);
    assert.equal(observed.result.code, 1);
    assert.equal(observed.result.signal, null);
    assert.match(observed.stderr, /invalid_broker_acceptance_configuration/);
    assert.equal(observed.stderr.includes(capability), false);
    await assert.rejects(readFile(observed.dockerCallsFile), {
      code: "ENOENT",
    });
  }
});

async function exerciseFakeDockerProbe(
  t,
  {
    signal,
    timeoutMs,
    phase = "build",
    reportUdpHit = false,
    reportUdpError = false,
    broker,
  },
) {
  const directory = await mkdtemp(
    path.join(os.tmpdir(), "agentsecret-egress-cancel-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));

  const readyFile = path.join(directory, "child-ready");
  const terminatedFile = path.join(directory, "child-terminated");
  const dockerGroupPidFile = path.join(directory, "docker-group-pid");
  const callsFile = path.join(directory, "docker-calls");
  const stateFile = path.join(directory, "docker-state.json");
  const docker = path.join(directory, "docker");
  const stub = `#!/usr/bin/env node
const fs = require("node:fs");
const { spawn } = require("node:child_process");
const command = process.argv[2];
const args = process.argv.slice(3);
const phase = ${JSON.stringify(phase)};
const reportUdpHit = ${JSON.stringify(reportUdpHit)};
const reportUdpError = ${JSON.stringify(reportUdpError)};
const stateFile = ${JSON.stringify(stateFile)};
let state = {};
try { state = JSON.parse(fs.readFileSync(stateFile, "utf8")); } catch {}
const saveState = () => fs.writeFileSync(stateFile, JSON.stringify(state));
fs.appendFileSync(${JSON.stringify(callsFile)}, JSON.stringify(process.argv.slice(2)) + "\\n");
if (command === "network" && args[0] === "create") {
  const ipam = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== "--subnet") continue;
    const subnet = args[++index];
    let gateway;
    if (args[index + 1] === "--gateway") {
      gateway = args[index + 2];
      index += 2;
    }
    ipam.push({ Subnet: subnet, ...(gateway ? { Gateway: gateway } : {}) });
  }
  state[args.includes("--internal") ? "internal" : "external"] = {
    name: args.at(-1),
    ipam,
  };
  saveState();
} else if (command === "run" && args.includes("--name")) {
  const name = args[args.indexOf("--name") + 1];
  state[name] = true;
  if (name.startsWith("agentsecret-egress-inspect-")) state.guestConfig = name;
  if (name.startsWith("agentsecret-egress-supervisor-")) state.supervisor = name;
  if (name.startsWith("agentsecret-egress-origin-")) state.origin = name;
  saveState();
}
if (
  command === "run" &&
  args.includes("/opt/linux-egress-supervisor.mjs") &&
  process.env.AGENTSECRET_TEST_BROKER_CAPABILITY
) {
  const envFileIndex = args.indexOf("--env-file");
  const envFile = args[envFileIndex + 1];
  const contents = fs.readFileSync(envFile, "utf8");
  state.brokerEnvFilePath = envFile;
  state.brokerEnvFileKeys = contents
    .trim()
    .split("\\n")
    .map((line) => line.split("=", 1)[0])
    .sort();
  state.brokerCapabilityInFile = contents.includes(
    "BROKER_CAPABILITY=" + process.env.AGENTSECRET_TEST_BROKER_CAPABILITY + "\\n",
  );
  state.brokerEnvFileMode = fs.statSync(envFile).mode & 0o777;
  saveState();
}
if (command === "logs" && reportUdpHit) {
  process.stdout.write("udp_witness_hit\\n");
} else if (command === "logs" && reportUdpError) {
  process.stdout.write("udp_witness_error:EIO\\n");
} else if (phase === "success" && command === "network" && args[0] === "inspect") {
  const network = [state.internal, state.external].find(
    (entry) => entry?.name === args.at(-1),
  );
  process.stdout.write(JSON.stringify(network?.ipam ?? []));
} else if (phase === "success" && command === "inspect") {
  const format = args[args.indexOf("--format") + 1];
  const target = args.at(-1);
  if (format.includes("NetworkSettings.Networks")) {
    if (target === state.guestConfig) {
      const internalIpv4 = state.internal.ipam.find((entry) => entry.Subnet.includes(".")).Subnet;
      const internalIpv6 = state.internal.ipam.find((entry) => entry.Subnet.includes(":")).Subnet;
      const ipv4Base = internalIpv4.split("/")[0].split(".").slice(0, 3).join(".");
      const ipv6Base = internalIpv6.split("/")[0].split("::")[0];
      process.stdout.write(JSON.stringify({
        [state.internal.name]: {
          IPAddress: ipv4Base + ".4",
          GlobalIPv6Address: ipv6Base + "::4",
        },
      }));
    } else {
      const host = target === state.supervisor ? "2" : "3";
      const externalIpv4 = state.external.ipam.find((entry) => entry.Subnet.includes(".")).Subnet;
      const externalIpv6 = state.external.ipam.find((entry) => entry.Subnet.includes(":")).Subnet;
      const ipv4Base = externalIpv4.split("/")[0].split(".").slice(0, 3).join(".");
      const ipv6Base = externalIpv6.split("/")[0].split("::")[0];
      process.stdout.write(JSON.stringify({
        [state.external.name]: {
          IPAddress: ipv4Base + "." + host,
          GlobalIPv6Address: ipv6Base + "::" + host,
        },
      }));
    }
  } else if (format.includes(".Mounts")) {
    process.stdout.write("[]");
  } else if (format.includes(".HostConfig")) {
    process.stdout.write(JSON.stringify({
      Privileged: false,
      ReadonlyRootfs: true,
      CapAdd: [],
      CapDrop: ["ALL"],
      Devices: [],
      Binds: [],
      SecurityOpt: ["no-new-privileges:true"],
    }));
  } else if (format.includes(".Config.User")) {
    process.stdout.write("node");
  }
} else if (phase === "success" && command === "run" && args.includes("/opt/linux-egress-guest.mjs")) {
  process.stdout.write("fake IPv4/IPv6 guest acceptance passed");
} else if (phase === "supervisor" && command === "run" && args.includes("/opt/linux-egress-supervisor.mjs")) {
  fs.writeFileSync(${JSON.stringify(readyFile)}, "ready");
  process.stderr.write("fake_supervisor_launch_failure\\n");
  process.exit(1);
} else if (command === "build" && phase === "build") {
  fs.writeFileSync(${JSON.stringify(dockerGroupPidFile)}, String(process.pid));
  const childCode = ${JSON.stringify(
    `const fs = require("node:fs");
process.on("SIGTERM", () => {
  fs.writeFileSync(${JSON.stringify(terminatedFile)}, "terminated");
  process.exit(0);
});
fs.writeFileSync(${JSON.stringify(readyFile)}, "ready");
setTimeout(() => {}, 60000);`,
  )};
  const child = spawn(process.execPath, ["-e", childCode], { stdio: "ignore" });
} else if (command === "run" && phase === "guest" && args.includes("/opt/linux-egress-guest.mjs")) {
  fs.writeFileSync(${JSON.stringify(dockerGroupPidFile)}, String(process.pid));
  const childCode = ${JSON.stringify(
    `const fs = require("node:fs");
process.on("SIGTERM", () => {
  fs.writeFileSync(${JSON.stringify(terminatedFile)}, "terminated");
  process.exit(0);
});
fs.writeFileSync(${JSON.stringify(readyFile)}, "ready");
setTimeout(() => {}, 60000);`,
  )};
  spawn(process.execPath, ["-e", childCode], { stdio: "ignore" });
} else if (command === "network" && args[0] === "inspect") {
  const network = [state.internal, state.external].find(
    (entry) => entry?.name === args.at(-1),
  );
  process.stdout.write(JSON.stringify(network?.ipam ?? []));
} else if (command === "inspect") {
  const network = state.external?.name;
  if (!network) process.exit(2);
  process.stdout.write(JSON.stringify({
    [network]: {
      IPAddress: "172.30.0.2",
      GlobalIPv6Address: "fd00:1234:5679::2",
    },
  }));
}
`;
  await writeFile(docker, stub);
  await chmod(docker, 0o755);

  const childEnv = {
    ...process.env,
    PATH: `${directory}${path.delimiter}${process.env.PATH ?? ""}`,
    AGENTSECRET_DOCKER_COMMAND_TIMEOUT_MS: String(timeoutMs),
  };
  for (const name of [
    "AGENTSECRET_EGRESS_BROKER_URL",
    "AGENTSECRET_EGRESS_BROKER_CAPABILITY",
    "AGENTSECRET_EGRESS_BROKER_ALIAS",
    "AGENTSECRET_EGRESS_BROKER_REQUEST_URL",
    "AGENTSECRET_TEST_BROKER_CAPABILITY",
  ])
    delete childEnv[name];
  if (broker) {
    childEnv.AGENTSECRET_EGRESS_BROKER_URL = broker.url;
    childEnv.AGENTSECRET_EGRESS_BROKER_CAPABILITY = broker.capability;
    childEnv.AGENTSECRET_EGRESS_BROKER_ALIAS = broker.alias;
    childEnv.AGENTSECRET_EGRESS_BROKER_REQUEST_URL = broker.requestUrl;
    childEnv.AGENTSECRET_TEST_BROKER_CAPABILITY = broker.capability;
  }
  const child = spawn(
    process.execPath,
    [path.join(root, "scripts/accept-linux-egress-boundary.mjs")],
    {
      cwd: root,
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => (stdout += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
  const closeResult = new Promise((resolve) => {
    child.once("close", (code, signal) => resolve({ code, signal }));
  });

  t.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill("SIGINT");
    try {
      await withTimeout(closeResult, 5000, "probe cleanup timed out");
    } catch {
      try {
        const groupPid = Number(await readFile(dockerGroupPidFile, "utf8"));
        process.kill(-groupPid, "SIGKILL");
      } catch {}
      child.kill("SIGKILL");
      await closeResult;
    }
  });

  if (phase !== "success") {
    try {
      await waitForFile(readyFile, timeoutMs + 1000);
    } catch (error) {
      throw new Error(
        `${error.message}; child_exit=${child.exitCode}; stderr=${stderr.trim()}`,
      );
    }
  }
  if (signal) child.kill(signal);
  const result = await withTimeout(
    closeResult,
    timeoutMs + 10_000,
    signal
      ? `probe did not exit after ${signal}`
      : "probe timeout did not exit",
  );
  if (phase === "build" || phase === "guest")
    assert.equal(await readFile(terminatedFile, "utf8"), "terminated");

  const dockerCalls = (await readFile(callsFile, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const dockerState = broker
    ? JSON.parse(await readFile(stateFile, "utf8"))
    : {};
  if (phase === "guest" || phase === "success")
    assertGuestRunHardening(dockerCalls, { broker });
  if (phase === "success") {
    const networkCreates = dockerCalls.filter(
      (args) => args[0] === "network" && args[1] === "create",
    );
    const internalCreate = networkCreates.find((args) =>
      args.includes("--internal"),
    );
    const externalCreate = networkCreates.find(
      (args) => !args.includes("--internal"),
    );
    const guestRun = dockerCalls.find(
      (args) =>
        args[0] === "run" && args.includes("/opt/linux-egress-guest.mjs"),
    );
    assert.equal(networkCreates.length, 2);
    assert.ok(internalCreate?.includes("--ipv6"));
    assert.ok(externalCreate?.includes("--ipv6"));
    const optionValues = (args, name) =>
      args.flatMap((value, index) => (value === name ? [args[index + 1]] : []));
    const internalSubnets = optionValues(internalCreate ?? [], "--subnet");
    const externalSubnets = optionValues(externalCreate ?? [], "--subnet");
    const internalGateways = optionValues(internalCreate ?? [], "--gateway");
    const externalGateways = optionValues(externalCreate ?? [], "--gateway");
    assert.equal(internalSubnets.length, 2);
    assert.equal(externalSubnets.length, 2);
    assert.equal(internalGateways.length, 2);
    assert.equal(externalGateways.length, 2);
    const internalIpv4Subnet = internalSubnets.find((value) =>
      value.includes("."),
    );
    const internalIpv6Subnet = internalSubnets.find((value) =>
      value.includes(":"),
    );
    const externalIpv4Subnet = externalSubnets.find((value) =>
      value.includes("."),
    );
    const externalIpv6Subnet = externalSubnets.find((value) =>
      value.includes(":"),
    );
    assert.match(internalIpv4Subnet, /^198\.19\.\d+\.0\/24$/);
    assert.match(externalIpv4Subnet, /^198\.18\.\d+\.0\/24$/);
    assert.match(
      internalIpv6Subnet,
      /^fd[0-9a-f]{2}:[0-9a-f]{4}:[0-9a-f]{4}::\/64$/,
    );
    assert.match(
      externalIpv6Subnet,
      /^fd[0-9a-f]{2}:[0-9a-f]{4}:[0-9a-f]{4}::\/64$/,
    );
    assert.notEqual(internalIpv4Subnet, externalIpv4Subnet);
    assert.notEqual(internalIpv6Subnet, externalIpv6Subnet);
    assert.ok(guestRun?.includes(`INTERNAL_GATEWAY_IP=${internalGateways[0]}`));
    assert.ok(
      guestRun?.includes(`INTERNAL_GATEWAY_IPV6=${internalGateways[1]}`),
    );
    const externalIpv6Prefix = externalIpv6Subnet.split("/")[0].split("::")[0];
    assert.ok(
      guestRun?.includes(`SUPERVISOR_EXTERNAL_IPV6=${externalIpv6Prefix}::2`),
    );
    assert.ok(
      guestRun?.includes(`ORIGIN_EXTERNAL_IPV6=${externalIpv6Prefix}::3`),
    );
  }
  const cleanupCalls = dockerCalls.filter(
    (args) =>
      args[0] === "rm" ||
      (args[0] === "network" && args[1] === "rm") ||
      (args[0] === "image" && args[1] === "rm"),
  );
  assert.equal(cleanupCalls.length, 6);
  assert.equal(cleanupCalls.filter((args) => args[0] === "rm").length, 3);
  assert.equal(
    cleanupCalls.filter((args) => args[0] === "network" && args[1] === "rm")
      .length,
    2,
  );
  assert.equal(cleanupCalls.filter((args) => args[0] === "image").length, 1);
  return { result, stderr, stdout, dockerCalls, dockerState };
}

for (const [signal, exitCode] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
]) {
  test(`Linux egress probe cleans Docker resources on ${signal}`, async (t) => {
    const observed = await exerciseFakeDockerProbe(t, {
      signal,
      timeoutMs: 10_000,
    });
    assert.deepEqual(observed.result, { code: exitCode, signal: null });
    assert.equal(observed.stderr.trim(), `docker_probe_cancelled:${signal}`);
    assert.equal(observed.stdout, "");
  });
}

test("Linux egress probe times out Docker work and cleans resources", async (t) => {
  const observed = await exerciseFakeDockerProbe(t, {
    timeoutMs: 15_000,
  });
  assert.equal(observed.result.code, 1);
  assert.equal(observed.result.signal, null);
  assert.match(observed.stderr, /docker_command_timed_out:build/);
  assert.equal(observed.stdout, "");
});

test("Linux egress probe cancels a running guest and cleans resources", async (t) => {
  const observed = await exerciseFakeDockerProbe(t, {
    phase: "guest",
    signal: "SIGINT",
    timeoutMs: 10_000,
  });
  assert.deepEqual(observed.result, { code: 130, signal: null });
  assert.equal(observed.stderr.trim(), "docker_probe_cancelled:SIGINT");
  assert.equal(observed.stdout, "");
});

test("Linux egress probe provisions IPv6 and wires gateway addresses to the isolated guest", async (t) => {
  const observed = await exerciseFakeDockerProbe(t, {
    timeoutMs: 10_000,
    phase: "success",
  });
  assert.deepEqual(observed.result, { code: 0, signal: null });
  assert.equal(observed.stderr, "");
  assert.match(observed.stdout, /IPv4\/IPv6 guest acceptance passed/);
});

test("Linux egress probe passes a one-use broker capability only to the supervisor", async (t) => {
  const broker = {
    url: "https://broker.example.test",
    capability: `aspc1.default.${"A".repeat(43)}`,
    alias: "TEST",
    requestUrl: "https://api.github.com/check",
  };
  const observed = await exerciseFakeDockerProbe(t, {
    timeoutMs: 10_000,
    phase: "success",
    broker,
  });
  assert.deepEqual(observed.result, { code: 0, signal: null });
  assert.equal(observed.stderr, "");
  assert.match(observed.stdout, /IPv4\/IPv6 guest acceptance passed/);
  assert.deepEqual(observed.dockerState.brokerEnvFileKeys, [
    "BROKER_ALIAS",
    "BROKER_CAPABILITY",
    "BROKER_URL",
    "UPSTREAM_BODY_URL",
  ]);
  assert.equal(observed.dockerState.brokerCapabilityInFile, true);
  assert.equal(observed.dockerState.brokerEnvFileMode, 0o600);
  assert.ok(
    observed.dockerCalls.every((args) =>
      args.every((argument) => !argument.includes(broker.capability)),
    ),
    "broker capability is never placed in Docker command arguments",
  );
});

test("Linux egress probe removes the broker capability file after supervisor success or failure", async (t) => {
  const broker = {
    url: "https://broker.example.test",
    capability: `aspc1.default.${"B".repeat(43)}`,
    alias: "TEST",
    requestUrl: "https://api.github.com/check",
  };
  const successful = await exerciseFakeDockerProbe(t, {
    timeoutMs: 10_000,
    phase: "success",
    broker,
  });
  const successPath = successful.dockerState.brokerEnvFilePath;
  assert.ok(successPath);
  await assert.rejects(readFile(successPath), { code: "ENOENT" });

  const failed = await exerciseFakeDockerProbe(t, {
    timeoutMs: 10_000,
    phase: "supervisor",
    broker,
  });
  assert.equal(failed.result.code, 1);
  assert.match(failed.stderr, /fake_supervisor_launch_failure/);
  const failedPath = failed.dockerState.brokerEnvFilePath;
  assert.ok(failedPath);
  await assert.rejects(readFile(failedPath), { code: "ENOENT" });
});

test("Linux egress probe rejects UDP witness hits and cleans resources", async (t) => {
  const observed = await exerciseFakeDockerProbe(t, {
    phase: "success",
    timeoutMs: 10_000,
    reportUdpHit: true,
  });
  assert.equal(observed.result.code, 1);
  assert.equal(observed.result.signal, null);
  assert.match(observed.stderr, /udp_witness_reachable/);
  assert.equal(observed.stdout, "");
});

test("Linux egress probe rejects unavailable UDP witnesses and cleans resources", async (t) => {
  const observed = await exerciseFakeDockerProbe(t, {
    phase: "success",
    timeoutMs: 10_000,
    reportUdpError: true,
  });
  assert.equal(observed.result.code, 1);
  assert.equal(observed.result.signal, null);
  assert.match(observed.stderr, /udp_witness_unavailable/);
  assert.equal(observed.stdout, "");
});
