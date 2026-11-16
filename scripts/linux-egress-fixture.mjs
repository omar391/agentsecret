import { createServer } from "node:http";
import { TextDecoder } from "node:util";
import { listenUdpWitness } from "./linux-egress-udp-probes.mjs";

const expected = process.env.EXPECTED_SECRET;
if (!expected) throw new Error("fixture_secret_missing");
await listenUdpWitness(
  8082,
  () => console.log("udp_witness_hit"),
  (error) => console.log(`udp_witness_error:${error.code || "unknown"}`),
);

createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/healthz") {
    response.writeHead(204).end();
    return;
  }
  if (request.method === "POST" && request.url === "/body-check") {
    if (request.headers["content-type"] !== "application/json") {
      response.writeHead(415).end();
      return;
    }
    const chunks = [];
    let bytes = 0;
    for await (const chunk of request) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.byteLength;
      if (bytes > 4096) {
        response.writeHead(413).end();
        return;
      }
      chunks.push(buffer);
    }
    let input;
    try {
      input = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.concat(chunks, bytes),
        ),
      );
    } catch {
      response.writeHead(400).end();
      return;
    }
    const credential =
      input &&
      typeof input === "object" &&
      !Array.isArray(input) &&
      Object.keys(input).length === 1 &&
      Object.hasOwn(input, "credential")
        ? input.credential
        : undefined;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify({
        valid: credential === expected,
        reflected: typeof credential === "string" ? credential : "",
      }),
    );
    return;
  }
  if (request.method !== "GET" || request.url !== "/check") {
    response.writeHead(404).end();
    return;
  }
  response.setHeader("Content-Type", "application/json");
  response.end(
    JSON.stringify({
      ok: true,
      reflected: request.headers.authorization || "",
      valid: request.headers.authorization === `Bearer ${expected}`,
    }),
  );
}).listen(8081, "0.0.0.0");
