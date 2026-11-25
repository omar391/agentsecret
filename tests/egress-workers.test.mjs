import assert from "node:assert/strict";
import { test } from "node:test";
import { unit } from "./unit-helpers.mjs";

// On Cloudflare Workers the pinned socket path cannot run (no ALPN in workerd's
// node:tls; no TLS sockets to a raw IP), so pinnedFetch keeps its target and
// public-DNS checks and then uses the runtime fetch. These tests drive that path
// in Node by stubbing navigator and fetch.

const dnsAnswer = (type, data) =>
  Response.json({
    Status: 0,
    Answer: data.map((address) => ({ type, data: address })),
  });

async function asWorkers(fetchImpl, run) {
  const originalFetch = globalThis.fetch;
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", {
    value: { userAgent: "Cloudflare-Workers" },
    configurable: true,
  });
  globalThis.fetch = fetchImpl;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
    if (descriptor) Object.defineProperty(globalThis, "navigator", descriptor);
    else delete globalThis.navigator;
  }
}

test("Node is not treated as the Workers runtime", () => {
  assert.equal(unit.isWorkersRuntime(), false);
});

test("Workers egress checks public DNS before sending through fetch with manual redirects", async () => {
  const calls = [];
  const response = await asWorkers(
    async (input, init = {}) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.startsWith("https://cloudflare-dns.com/dns-query")) {
        const type = new URL(url).searchParams.get("type");
        return type === "A"
          ? dnsAnswer(1, ["93.184.216.34"])
          : dnsAnswer(28, []);
      }
      return new Response("ok-body", {
        status: 200,
        headers: { "Content-Type": "text/plain", Connection: "keep-alive" },
      });
    },
    () =>
      unit.pinnedFetch("https://api.vendor.dev/v1/items?x=1", {
        method: "POST",
        headers: { Authorization: "Bearer synthetic", "X-Test": "1" },
        body: '{"a":1}',
      }),
  );
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "ok-body");
  assert.equal(response.headers.get("connection"), null);
  const upstream = calls.find((call) =>
    call.url.startsWith("https://api.vendor.dev/"),
  );
  assert.ok(upstream, "upstream request sent");
  assert.ok(
    calls.findIndex((call) => call.url.includes("dns-query")) <
      calls.indexOf(upstream),
    "DNS check happens before the upstream request",
  );
  assert.equal(upstream.init.redirect, "manual");
  assert.equal(upstream.init.method, "POST");
  assert.equal(upstream.init.body, '{"a":1}');
  const sent = new Headers(upstream.init.headers);
  assert.equal(sent.get("authorization"), "Bearer synthetic");
  assert.equal(sent.get("accept-encoding"), "identity");
  assert.equal(sent.get("host"), null);
  assert.equal(sent.get("connection"), null);
});

test("Workers egress refuses private DNS answers and SSRF targets without contacting them", async () => {
  const contacted = [];
  const privateAnswer = (input) => {
    const url = String(input);
    contacted.push(url);
    if (url.startsWith("https://cloudflare-dns.com/dns-query")) {
      const type = new URL(url).searchParams.get("type");
      return Promise.resolve(
        type === "A" ? dnsAnswer(1, ["10.0.0.8"]) : dnsAnswer(28, []),
      );
    }
    return Promise.resolve(new Response("should not be reached"));
  };
  await asWorkers(privateAnswer, async () => {
    await assert.rejects(
      unit.pinnedFetch("https://rebind.vendor.dev/", { method: "GET" }),
      /unsafe_dns_answer/,
    );
    await assert.rejects(
      unit.pinnedFetch("https://127.0.0.1/", { method: "GET" }),
      /unsupported_pinned_target/,
    );
    await assert.rejects(
      unit.pinnedFetch("http://api.vendor.dev/", { method: "GET" }),
      /unsupported_pinned_target/,
    );
  });
  assert.ok(
    contacted.every((url) => url.startsWith("https://cloudflare-dns.com/")),
    "only the DNS resolver was contacted",
  );
});

test("Workers egress keeps request-shape rules and response limits", async () => {
  const url = new URL("https://api.vendor.dev/x");
  await assert.rejects(
    unit.workersFetch(url, { method: "GET", headers: { Connection: "x" } }),
    /unsupported_request_header/,
  );
  await assert.rejects(
    unit.workersFetch(url, { method: "POST", body: new Uint8Array([1]) }),
    /unsupported_request_body/,
  );
  await assert.rejects(
    unit.workersFetch(url, { method: "TRACE" }),
    /unsupported_request_method/,
  );
  const large = new Uint8Array(512 * 1024 + 1);
  await assert.rejects(
    unit.workersFetch(url, { method: "GET" }, async () => new Response(large)),
    /upstream_response_too_large/,
  );
  const redirect = await unit.workersFetch(
    url,
    { method: "GET" },
    async () =>
      new Response(null, {
        status: 302,
        headers: { Location: "https://elsewhere.vendor.dev/" },
      }),
  );
  assert.equal(redirect.status, 302);
  assert.equal(
    redirect.headers.get("location"),
    "https://elsewhere.vendor.dev/",
  );
  const head = await unit.workersFetch(
    url,
    { method: "HEAD" },
    async () => new Response("ignored", { status: 200 }),
  );
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");
});
