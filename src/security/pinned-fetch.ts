import { connect as tlsConnect } from "node:tls";
import { isSsrfTarget } from "./policy";

const DNS_JSON_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const MAX_DNS_RESPONSE_BYTES = 32 * 1024;
const MAX_RESPONSE_HEADER_BYTES = 32 * 1024;
const MAX_RESPONSE_BODY_BYTES = 512 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

type TlsSocket = import("node:tls").TLSSocket;

/**
 * Fetch an HTTPS URL only after validating every DNS address and connecting to
 * one of those exact addresses. The original DNS name remains the TLS identity
 * and HTTP Host value. This intentionally supports bounded HTTP/1.x only.
 */
export async function pinnedFetch(
  urlText: string,
  init: RequestInit,
  options: { allowNonStandardPort?: boolean } = {},
): Promise<Response> {
  const url = new URL(urlText);
  const port = url.port ? Number(url.port) : 443;
  if (
    url.protocol !== "https:" ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535 ||
    (port !== 443 && options.allowNonStandardPort !== true) ||
    url.username ||
    url.password ||
    url.hash ||
    isSsrfTarget(url.hostname)
  ) {
    throw new Error("unsupported_pinned_target");
  }

  const literal = normalizeIpLiteral(url.hostname);
  const addresses = literal
    ? [literal]
    : await resolvePublicAddresses(url.hostname);
  // Do not retry another address after a request may have reached the origin:
  // a lost or malformed response can follow a committed mutation.
  return requestPinnedAddress(url, init, addresses[0], port);
}

function normalizeIpLiteral(hostname: string): string | undefined {
  const value =
    hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value)) {
    const parts = value.split(".");
    if (parts.every((part) => Number(part) <= 255)) return value;
    throw new Error("unsafe_dns_answer");
  }
  if (value.includes(":")) {
    try {
      new URL(`https://[${value}]/`);
      return value;
    } catch {
      throw new Error("unsafe_dns_answer");
    }
  }
  return undefined;
}

async function resolvePublicAddresses(hostname: string): Promise<string[]> {
  const queries = await Promise.all(
    (["A", "AAAA"] as const).map(async (type) => {
      const query = new URL(DNS_JSON_ENDPOINT);
      query.searchParams.set("name", hostname);
      query.searchParams.set("type", type);
      const response = await fetch(query, {
        method: "GET",
        headers: { Accept: "application/dns-json" },
        redirect: "manual",
        cache: "no-store",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.status !== 200) {
        await response.body?.cancel();
        throw new Error("dns_resolution_failed");
      }
      const text = await readBoundedText(response, MAX_DNS_RESPONSE_BYTES);
      let result: unknown;
      try {
        result = JSON.parse(text);
      } catch {
        throw new Error("invalid_dns_response");
      }
      return parseDnsAnswers(result, type);
    }),
  );
  const addresses = [...new Set(queries.flat())];
  if (!addresses.length || addresses.some(isSsrfTarget)) {
    throw new Error("unsafe_dns_answer");
  }
  return addresses;
}

export function parseDnsAnswers(
  input: unknown,
  queryType: "A" | "AAAA",
): string[] {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("invalid_dns_response");
  }
  const value = input as { Status?: unknown; Answer?: unknown };
  if (
    value.Status !== 0 ||
    !Array.isArray(value.Answer) ||
    value.Answer.length > 32
  ) {
    if (value.Status === 0 && value.Answer === undefined) return [];
    throw new Error("dns_resolution_failed");
  }
  const expectedType = queryType === "A" ? 1 : 28;
  const result: string[] = [];
  for (const answer of value.Answer) {
    if (!answer || typeof answer !== "object" || Array.isArray(answer)) {
      throw new Error("invalid_dns_response");
    }
    const record = answer as { type?: unknown; data?: unknown };
    if (record.type === 5) continue; // CNAME; inspect the final A/AAAA records.
    if (record.type !== expectedType) continue;
    if (
      typeof record.data !== "string" ||
      !isAddressForType(record.data, queryType) ||
      isSsrfTarget(record.data)
    ) {
      throw new Error("unsafe_dns_answer");
    }
    result.push(record.data);
  }
  return result;
}

function isAddressForType(address: string, queryType: "A" | "AAAA"): boolean {
  if (queryType === "A") {
    const parts = address.split(".");
    return (
      parts.length === 4 &&
      parts.every(
        (part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255,
      )
    );
  }
  if (!address.includes(":")) return false;
  try {
    return new URL(`https://[${address}]/`).hostname.length > 0;
  } catch {
    return false;
  }
}

async function readBoundedText(
  response: Response,
  limit: number,
): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new Error("response_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
      bytes,
    );
  } catch {
    throw new Error("invalid_dns_response");
  }
}

function requestPinnedAddress(
  url: URL,
  init: RequestInit,
  address: string,
  port: number,
): Promise<Response> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let received: Uint8Array = new Uint8Array();
    let dataEvents = 0;
    let ended = false;
    let socket: TlsSocket;

    const finish = (error?: unknown, response?: Response) => {
      if (settled) return;
      settled = true;
      socket?.destroy();
      if (error) reject(error);
      else resolve(response!);
    };

    try {
      socket = tlsConnect(
        {
          host: address,
          port,
          ...(normalizeIpLiteral(url.hostname)
            ? {}
            : { servername: url.hostname }),
          rejectUnauthorized: true,
          ALPNProtocols: ["http/1.1"],
          timeout: REQUEST_TIMEOUT_MS,
        },
        () => {
          if (
            !socket.authorized ||
            (socket.alpnProtocol && socket.alpnProtocol !== "http/1.1")
          ) {
            finish(new Error("tls_verification_failed"));
            return;
          }
          try {
            socket.write(serializeRequest(url, init));
          } catch (error) {
            finish(error);
          }
        },
      );
      socket.setTimeout(REQUEST_TIMEOUT_MS, () =>
        finish(new Error("upstream_timeout")),
      );
      socket.on("data", (chunk: Uint8Array) => {
        if (settled) return;
        dataEvents++;
        if (dataEvents > 256) {
          finish(new Error("upstream_response_fragmented"));
          return;
        }
        if (
          received.byteLength + chunk.byteLength >
          MAX_RESPONSE_HEADER_BYTES + MAX_RESPONSE_BODY_BYTES + 16_384
        ) {
          finish(new Error("upstream_response_too_large"));
          return;
        }
        received = concat(received, chunk);
        try {
          const parsed = parseHttpResponse(received, ended, init.method);
          if (parsed) finish(undefined, parsed);
        } catch (error) {
          finish(error);
        }
      });
      socket.on("end", () => {
        ended = true;
        try {
          const parsed = parseHttpResponse(received, true, init.method);
          if (!parsed) finish(new Error("truncated_upstream_response"));
          else finish(undefined, parsed);
        } catch (error) {
          finish(error);
        }
      });
      socket.on("close", () => {
        if (!settled) finish(new Error("upstream_connection_closed"));
      });
      socket.on("error", (error: Error) => finish(error));
    } catch (error) {
      finish(error);
    }
  });
}

function serializeRequest(url: URL, init: RequestInit): string {
  const method = init.method || "GET";
  if (!/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(method)) {
    throw new Error("unsupported_request_method");
  }
  const headers = new Headers(init.headers);
  if (
    [...headers.keys()].some((name) =>
      HOP_BY_HOP_HEADERS.has(name.toLowerCase()),
    )
  ) {
    throw new Error("unsupported_request_header");
  }
  if (
    init.body !== undefined &&
    init.body !== null &&
    typeof init.body !== "string"
  ) {
    throw new Error("unsupported_request_body");
  }
  const body = typeof init.body === "string" ? init.body : "";
  headers.set("Host", url.host);
  headers.set("Connection", "close");
  headers.set("Accept-Encoding", "identity");
  headers.set(
    "Content-Length",
    String(new TextEncoder().encode(body).byteLength),
  );
  const startLine = `${method} ${url.pathname}${url.search || ""} HTTP/1.1\r\n`;
  const fields = [...headers.entries()]
    .map(([name, value]) => `${name}: ${value}\r\n`)
    .join("");
  return `${startLine}${fields}\r\n${body}`;
}

export function parseHttpResponse(
  bytes: Uint8Array,
  ended: boolean,
  method = "GET",
): Response | undefined {
  const headerEnd = indexOfBytes(bytes, [13, 10, 13, 10]);
  if (headerEnd < 0) {
    if (bytes.byteLength > MAX_RESPONSE_HEADER_BYTES)
      throw new Error("invalid_upstream_headers");
    if (ended) throw new Error("truncated_upstream_headers");
    return undefined;
  }
  if (headerEnd > MAX_RESPONSE_HEADER_BYTES)
    throw new Error("invalid_upstream_headers");
  const headerBytes = bytes.subarray(0, headerEnd);
  if (
    headerBytes.some(
      (byte) => (byte < 0x20 && byte !== 0x0d && byte !== 0x0a) || byte > 0x7e,
    )
  ) {
    throw new Error("invalid_upstream_headers");
  }
  const head = new TextDecoder("ascii", {
    fatal: true,
    ignoreBOM: false,
  }).decode(headerBytes);
  const lines = head.split("\r\n");
  const status = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?$/.exec(
    lines.shift() || "",
  );
  if (!status) throw new Error("invalid_upstream_status");
  const statusCode = Number(status[1]);
  if (statusCode < 200 || statusCode > 599)
    throw new Error("unsupported_upstream_status");
  const headers = new Headers();
  let contentLength: number | undefined;
  let transferEncoding: string | undefined;
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator < 1 || /^[ \t]/.test(line))
      throw new Error("invalid_upstream_headers");
    const name = line.slice(0, separator);
    const value = line.slice(separator + 1).trim();
    if (
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
      /[\x00-\x08\x0a-\x1f\x7f]/.test(value)
    ) {
      throw new Error("invalid_upstream_headers");
    }
    const lower = name.toLowerCase();
    if (lower === "content-length") {
      if (contentLength !== undefined || !/^\d{1,9}$/.test(value))
        throw new Error("invalid_upstream_framing");
      contentLength = Number(value);
      if (contentLength > MAX_RESPONSE_BODY_BYTES)
        throw new Error("upstream_response_too_large");
    } else if (lower === "transfer-encoding") {
      if (transferEncoding !== undefined)
        throw new Error("invalid_upstream_framing");
      transferEncoding = value.toLowerCase();
    }
    if (!HOP_BY_HOP_HEADERS.has(lower)) headers.append(name, value);
  }
  if (contentLength !== undefined && transferEncoding !== undefined)
    throw new Error("invalid_upstream_framing");
  if (transferEncoding !== undefined && transferEncoding !== "chunked")
    throw new Error("unsupported_upstream_framing");
  const bodyStart = headerEnd + 4;
  const bodyBytes = bytes.subarray(bodyStart);
  const bodyless = method === "HEAD" || [204, 205, 304].includes(statusCode);
  if (bodyless) {
    if (bodyBytes.byteLength !== 0) throw new Error("invalid_upstream_framing");
    return new Response(null, { status: statusCode, headers });
  }

  let body: Uint8Array | undefined;
  if (transferEncoding === "chunked") {
    body = decodeChunkedBody(bodyBytes, ended);
    if (!body) return undefined;
  } else if (contentLength !== undefined) {
    if (bodyBytes.byteLength < contentLength) {
      if (ended) throw new Error("truncated_upstream_body");
      return undefined;
    }
    if (bodyBytes.byteLength !== contentLength)
      throw new Error("invalid_upstream_framing");
    body = bodyBytes;
  } else {
    if (!ended) return undefined;
    if (bodyBytes.byteLength > MAX_RESPONSE_BODY_BYTES)
      throw new Error("upstream_response_too_large");
    body = bodyBytes;
  }
  return new Response(body === undefined ? null : new Uint8Array(body).buffer, {
    status: statusCode,
    headers,
  });
}

function decodeChunkedBody(
  bytes: Uint8Array,
  ended: boolean,
): Uint8Array | undefined {
  const output: Uint8Array[] = [];
  let offset = 0;
  let size = 0;
  let chunks = 0;
  while (true) {
    const lineEnd = indexOfBytes(bytes, [13, 10], offset);
    if (lineEnd < 0) {
      if (ended) throw new Error("truncated_upstream_body");
      return undefined;
    }
    if (lineEnd - offset > 1024) throw new Error("invalid_chunked_body");
    const line = new TextDecoder("ascii", {
      fatal: true,
      ignoreBOM: false,
    }).decode(bytes.subarray(offset, lineEnd));
    const match = /^([0-9a-fA-F]{1,8})(?:;[\x20-\x7e]*)?$/.exec(line);
    if (!match) throw new Error("invalid_chunked_body");
    const length = Number.parseInt(match[1], 16);
    offset = lineEnd + 2;
    if (length === 0) {
      // This adapter does not expose trailers. Accept the empty trailer section
      // only; nonempty or malformed trailers fail closed.
      if (bytes.byteLength < offset + 2) {
        if (ended) throw new Error("truncated_upstream_body");
        return undefined;
      }
      if (
        bytes[offset] !== 13 ||
        bytes[offset + 1] !== 10 ||
        offset + 2 !== bytes.byteLength
      ) {
        throw new Error("unsupported_upstream_trailers");
      }
      return concatMany(output);
    }
    if (++chunks > 4096) throw new Error("upstream_response_fragmented");
    if (size + length > MAX_RESPONSE_BODY_BYTES)
      throw new Error("upstream_response_too_large");
    if (bytes.byteLength < offset + length + 2) {
      if (ended) throw new Error("truncated_upstream_body");
      return undefined;
    }
    if (bytes[offset + length] !== 13 || bytes[offset + length + 1] !== 10)
      throw new Error("invalid_chunked_body");
    output.push(bytes.subarray(offset, offset + length));
    size += length;
    offset += length + 2;
  }
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const result = new Uint8Array(left.byteLength + right.byteLength);
  result.set(left, 0);
  result.set(right, left.byteLength);
  return result;
}

function concatMany(chunks: Uint8Array[]): Uint8Array {
  const size = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function indexOfBytes(
  haystack: Uint8Array,
  needle: number[],
  from = 0,
): number {
  for (
    let index = from;
    index <= haystack.byteLength - needle.length;
    index++
  ) {
    if (needle.every((byte, position) => haystack[index + position] === byte))
      return index;
  }
  return -1;
}
