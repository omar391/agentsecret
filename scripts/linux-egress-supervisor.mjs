import { createServer } from "node:http";
import { TextDecoder } from "node:util";
import { listenUdpWitness } from "./linux-egress-udp-probes.mjs";

const secret = process.env.SYNTHETIC_SECRET;
const capability = process.env.RUN_CAPABILITY;
const brokerUrl = process.env.BROKER_URL;
const brokerCapability = process.env.BROKER_CAPABILITY;
const brokerAlias = process.env.BROKER_ALIAS ?? "fixture";
const placeholder = "AGENTSECRET_SECRET_FIXTURE";
const bodyPlaceholder = "{{AGENTSECRET_SECRET}}";
const upstreamUrl = process.env.UPSTREAM_URL ?? "http://origin:8081/check";
const upstreamBodyUrl =
  process.env.UPSTREAM_BODY_URL ?? "http://origin:8081/body-check";
const upstreamHealthUrl =
  process.env.UPSTREAM_HEALTH_URL ?? "http://origin:8081/healthz";
const supervisorHost = process.env.SUPERVISOR_HOST ?? "0.0.0.0";
const supervisorPort = Number(process.env.SUPERVISOR_PORT ?? 8080);
const maxUpstreamResponseBytes = 512 * 1024;
const brokerMode = brokerUrl !== undefined || brokerCapability !== undefined;
let brokerEndpoint;
if (brokerMode) {
  if (
    secret !== undefined ||
    !brokerUrl ||
    !brokerCapability ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(brokerAlias)
  )
    throw new Error("supervisor_configuration_missing");
  const parsedBrokerUrl = new URL(brokerUrl);
  if (
    !["http:", "https:"].includes(parsedBrokerUrl.protocol) ||
    parsedBrokerUrl.username ||
    parsedBrokerUrl.password ||
    parsedBrokerUrl.pathname !== "/" ||
    parsedBrokerUrl.search ||
    parsedBrokerUrl.hash ||
    (parsedBrokerUrl.protocol !== "https:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(parsedBrokerUrl.hostname))
  )
    throw new Error("broker_url_invalid");
  brokerEndpoint = new URL("/proxy/capability", parsedBrokerUrl).toString();
} else if (!secret) {
  throw new Error("supervisor_configuration_missing");
}
if (!capability) throw new Error("supervisor_configuration_missing");
await listenUdpWitness(
  Number(process.env.UDP_WITNESS_PORT ?? 8082),
  () => console.log("udp_witness_hit"),
  (error) => console.log(`udp_witness_error:${error.code || "unknown"}`),
);
let capabilityConsumed = false;
let dispatches = 0;

function hasCapability(value) {
  const expected = `AgentSecret ${capability}`;
  if (typeof value !== "string" || value.length !== expected.length)
    return false;
  let difference = 0;
  for (let index = 0; index < expected.length; index++)
    difference |= value.charCodeAt(index) ^ expected.charCodeAt(index);
  return difference === 0;
}

function hasBodyPlaceholder(value) {
  if (typeof value !== "string") return undefined;
  let body;
  try {
    body = JSON.parse(value);
  } catch {
    return undefined;
  }
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    Object.keys(body).length !== 1 ||
    !Object.hasOwn(body, "credential") ||
    body.credential !== bodyPlaceholder
  )
    return false;
  return true;
}

async function readUpstreamJson(upstream) {
  if (!upstream.body) throw new Error("fixture_response_body_missing");
  const reader = upstream.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      bytes += chunk.byteLength;
      if (bytes > maxUpstreamResponseBytes) {
        await reader.cancel().catch(() => {});
        throw new Error("fixture_response_too_large");
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }
  const body = Buffer.concat(chunks, bytes);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  return JSON.parse(text);
}

createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/healthz") {
    try {
      const health = await fetch(upstreamHealthUrl, {
        redirect: "manual",
        signal: AbortSignal.timeout(1000),
      });
      response.writeHead(health.ok ? 200 : 503, {
        "content-type": "application/json",
      });
      response.end(JSON.stringify({ ready: health.ok, dispatches }));
    } catch {
      response.writeHead(503).end();
    }
    return;
  }
  if (
    request.method !== "POST" ||
    !["/v1/request", "/v1/body-request"].includes(request.url) ||
    (brokerMode && request.url !== "/v1/body-request") ||
    !hasCapability(request.headers.authorization)
  ) {
    response.writeHead(403).end();
    return;
  }
  const bodyChunks = [];
  let bodyBytes = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bodyBytes += bytes.byteLength;
    if (bodyBytes > 4096) {
      response.writeHead(413).end();
      return;
    }
    bodyChunks.push(bytes);
  }
  let input;
  try {
    const body = Buffer.concat(bodyChunks, bodyBytes);
    input = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    response.writeHead(400).end();
    return;
  }
  const bodyRequest = request.url === "/v1/body-request";
  const expectedInputKeys = bodyRequest
    ? ["alias", "url", "method", "headers", "body"]
    : ["alias", "url", "method", "headers"];
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).length !== expectedInputKeys.length ||
    expectedInputKeys.some((key) => !Object.hasOwn(input, key))
  ) {
    response.writeHead(400).end();
    return;
  }
  let upstreamRequest;
  if (bodyRequest) {
    const expectedAlias = brokerMode ? brokerAlias : "fixture";
    if (
      input.alias !== expectedAlias ||
      input.url !== upstreamBodyUrl ||
      input.method !== "POST" ||
      !input.headers ||
      typeof input.headers !== "object" ||
      Array.isArray(input.headers) ||
      Object.keys(input.headers).length !== 1 ||
      input.headers["content-type"] !== "application/json" ||
      !hasBodyPlaceholder(input.body)
    ) {
      response.writeHead(403).end();
      return;
    }
    upstreamRequest = {
      alias: input.alias,
      url: input.url,
      method: input.method,
      headers: { "content-type": "application/json" },
      body: brokerMode ? input.body : JSON.stringify({ credential: secret }),
      expectedReflection: brokerMode ? undefined : secret,
      redactedField: "credential",
    };
  } else {
    if (
      input.alias !== "fixture" ||
      input.url !== upstreamUrl ||
      input.method !== "GET" ||
      !input.headers ||
      typeof input.headers !== "object" ||
      Array.isArray(input.headers) ||
      Object.keys(input.headers).length !== 1 ||
      input.headers.authorization !== `Bearer ${placeholder}`
    ) {
      response.writeHead(403).end();
      return;
    }
    upstreamRequest = {
      url: input.url,
      method: input.method,
      headers: { authorization: `Bearer ${secret}` },
      expectedReflection: `Bearer ${secret}`,
      redactedField: "authorization",
    };
  }
  if (capabilityConsumed) {
    response.writeHead(409).end();
    return;
  }
  capabilityConsumed = true;
  dispatches++;
  try {
    const brokerRequest = brokerMode
      ? {
          secret_alias: upstreamRequest.alias,
          url: upstreamRequest.url,
          method: upstreamRequest.method,
          headers: upstreamRequest.headers,
          body: upstreamRequest.body,
        }
      : undefined;
    const upstream = await fetch(
      brokerMode ? brokerEndpoint : upstreamRequest.url,
      {
        method: brokerMode ? "POST" : upstreamRequest.method,
        headers: brokerMode
          ? {
              authorization: `AgentSecret ${brokerCapability}`,
              "content-type": "application/json",
            }
          : upstreamRequest.headers,
        ...(brokerMode
          ? { body: JSON.stringify(brokerRequest) }
          : upstreamRequest.body === undefined
            ? {}
            : { body: upstreamRequest.body }),
        redirect: "manual",
        signal: AbortSignal.timeout(2000),
      },
    );
    if (upstream.status >= 300 && upstream.status < 400) {
      await upstream.body?.cancel();
      throw new Error("fixture_redirect_refused");
    }
    const result = await readUpstreamJson(upstream);
    if (brokerMode) {
      if (
        !upstream.ok ||
        !result ||
        typeof result !== "object" ||
        Array.isArray(result) ||
        !Number.isSafeInteger(result.status) ||
        result.status < 200 ||
        result.status >= 300 ||
        result.redirectBlocked === true ||
        !Object.hasOwn(result, "data")
      )
        throw new Error("broker_request_failed");
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({ ok: true, status: result.status, data: result.data }),
      );
      return;
    }
    if (
      !upstream.ok ||
      result.valid !== true ||
      result.reflected !== upstreamRequest.expectedReflection
    )
      throw new Error("fixture_verification_failed");
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        ok: true,
        [upstreamRequest.redactedField]: "[REDACTED]",
      }),
    );
  } catch {
    response.writeHead(502).end();
  }
}).listen(supervisorPort, supervisorHost);
