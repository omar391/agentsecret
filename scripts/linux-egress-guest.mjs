import assert from "node:assert/strict";
import {
  assertTcpUnreachable,
  tcpBypassTargets,
} from "./linux-egress-tcp-probes.mjs";
import {
  assertUdpUnreachable,
  udpBypassTargets,
} from "./linux-egress-udp-probes.mjs";

const supervisor = "http://supervisor:8080";
const bodyPlaceholder = process.env.BODY_PLACEHOLDER;
const requestAlias = process.env.REQUEST_ALIAS ?? "fixture";
const requestUrl =
  process.env.REQUEST_BODY_URL ?? "http://origin:8081/body-check";
const brokerMode = process.env.BROKER_MODE === "1";
if (bodyPlaceholder !== "{{AGENTSECRET_SECRET}}")
  throw new Error("body_placeholder_missing");
async function waitForSupervisor() {
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      if (
        (
          await fetch(`${supervisor}/healthz`, {
            signal: AbortSignal.timeout(500),
          })
        ).ok
      )
        return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("supervisor_unavailable");
}
await waitForSupervisor();
const capabilityHeaders = {
  authorization: `AgentSecret ${process.env.RUN_CAPABILITY}`,
  "content-type": "application/json",
};
const requestBody = (url, method = "POST", credential = bodyPlaceholder) =>
  JSON.stringify({
    alias: requestAlias,
    url,
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ credential }),
  });
const bodyRequestEndpoint = `${supervisor}/v1/body-request`;
const denied = await fetch(bodyRequestEndpoint, {
  method: "POST",
  headers: capabilityHeaders,
  body: requestBody("http://example.com/body-check"),
});
assert.equal(denied.status, 403);
const wrongMethod = await fetch(bodyRequestEndpoint, {
  method: "POST",
  headers: capabilityHeaders,
  body: requestBody(requestUrl, "GET"),
});
assert.equal(wrongMethod.status, 403);
const wrongPlaceholder = await fetch(bodyRequestEndpoint, {
  method: "POST",
  headers: capabilityHeaders,
  body: requestBody(requestUrl, "POST", "literal-secret"),
});
assert.equal(wrongPlaceholder.status, 403);
const allowed = await fetch(bodyRequestEndpoint, {
  method: "POST",
  headers: capabilityHeaders,
  body: requestBody(requestUrl),
});
assert.equal(allowed.status, 200);
const allowedBody = await allowed.json();
if (brokerMode) {
  assert.equal(allowedBody.ok, true);
  assert.ok(Number.isSafeInteger(allowedBody.status));
  assert.ok(allowedBody.status >= 200 && allowedBody.status < 300);
  assert.ok(!JSON.stringify(allowedBody).includes(bodyPlaceholder));
} else {
  assert.deepEqual(allowedBody, {
    ok: true,
    credential: "[REDACTED]",
  });
}
const replay = await fetch(bodyRequestEndpoint, {
  method: "POST",
  headers: capabilityHeaders,
  body: requestBody(requestUrl),
});
assert.equal(replay.status, 409);
assert.ok(!(await replay.text()).includes("literal-secret"));
const health = await fetch(`${supervisor}/healthz`);
assert.deepEqual(await health.json(), { ready: true, dispatches: 1 });

async function assertUnreachable(label, url) {
  let reached = false;
  try {
    await fetch(url, { signal: AbortSignal.timeout(1500) });
    reached = true;
  } catch {}
  assert.equal(reached, false, `${label}_reachable`);
}
await assertUnreachable("external_dns", "http://example.com/");
await assertUnreachable(
  "aws_compatible_metadata_ip",
  "http://169.254.169.254/latest/meta-data/",
);
await assertUnreachable(
  "alibaba_metadata_ip",
  "http://100.100.100.200/latest/meta-data/",
);
await assertUnreachable(
  "ipv6_metadata_ip",
  "http://[fd00:ec2::254]/latest/meta-data/",
);
await assertUnreachable(
  "google_metadata_hostname",
  "http://metadata.google.internal/computeMetadata/v1/",
);
await assertUnreachable(
  "external_supervisor_address",
  `http://${process.env.SUPERVISOR_EXTERNAL_IP}:8080/v1/body-request`,
);
await assertUnreachable(
  "external_supervisor_ipv6_address",
  `http://[${process.env.SUPERVISOR_EXTERNAL_IPV6}]:8080/v1/body-request`,
);
await assertUnreachable(
  "external_origin_address",
  `http://${process.env.ORIGIN_EXTERNAL_IP}:8081/check`,
);
await assertUnreachable(
  "external_origin_ipv6_address",
  `http://[${process.env.ORIGIN_EXTERNAL_IPV6}]:8081/check`,
);
await assertUnreachable(
  "dns_override",
  "http://override.example.test:8080/v1/request",
);
await assertUnreachable(
  "host_service",
  `http://host.docker.internal:${process.env.HOST_TRAP_PORT}/`,
);
await assertUnreachable(
  "host_bridge_gateway",
  `http://${process.env.INTERNAL_GATEWAY_IP}:${process.env.HOST_TRAP_PORT}/`,
);
await assertUnreachable(
  "host_ipv6_bridge_gateway",
  `http://[${process.env.INTERNAL_GATEWAY_IPV6}]:${process.env.HOST_TRAP_PORT}/`,
);

for (const target of tcpBypassTargets(process.env))
  await assertTcpUnreachable(target.label, target.host, target.port);
for (const target of udpBypassTargets(process.env))
  await assertUdpUnreachable(
    target.label,
    target.host,
    target.port,
    target.type,
  );
console.log(
  "synthetic egress boundary passed; this does not qualify a product runtime",
);
