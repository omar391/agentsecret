import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { Env } from "../types";
import { HttpError } from "../security/primitives";
import {
  handleApplicationRequest,
  type HostAdapters,
} from "../core/application";

async function readBody(request: IncomingMessage): Promise<Buffer | null> {
  if (request.method === "GET" || request.method === "HEAD") return null;
  const limit = 64 * 1024;
  const advertisedLength = Number(request.headers["content-length"] ?? 0);
  if (Number.isFinite(advertisedLength) && advertisedLength > limit) {
    request.resume();
    throw new HttpError(413, "request_too_large");
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.byteLength;
    if (size > limit) {
      request.resume();
      throw new HttpError(413, "request_too_large");
    }
    chunks.push(bytes);
  }
  return chunks.length === 0 ? null : Buffer.concat(chunks);
}

export function toHeaders(request: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (name.toLowerCase() === "cf-connecting-ip") continue;
    if (value === undefined) continue;
    if (Array.isArray(value))
      for (const item of value) headers.append(name, item);
    else headers.set(name, value);
  }
  // This adapter has no trusted-proxy configuration, so only the transport
  // peer may supply the identity consumed by shared rate-limit code.
  if (request.socket.remoteAddress)
    headers.set("cf-connecting-ip", request.socket.remoteAddress);
  return headers;
}

/**
 * The Node HTTP adapter for the application core.
 *
 * It is the Node counterpart of the Worker's `fetch` handler: each request
 * is adapted to a Fetch `Request`, passed through the same
 * `handleApplicationRequest` the Worker uses, and the `Response` is written
 * back. When `publicOrigin` is configured the request URL is rebuilt on that
 * origin so DPoP proofs, OAuth redirects and canonical links match the public
 * deployment exactly as they do behind the Cloudflare edge.
 */
export function createNodeServer(options: {
  env: Env;
  adapters: HostAdapters;
  publicOrigin?: string;
}): Server {
  const { env, adapters, publicOrigin } = options;
  return createServer((request, response) => {
    void handle(request, response);
  });

  async function handle(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    try {
      const body = await readBody(request);
      const host = request.headers.host ?? "localhost";
      const origin = publicOrigin ?? "http://" + host;
      const target = request.url ?? "/";
      // Node can expose network-path and absolute-form request targets here.
      // Never let URL resolution replace the configured public authority.
      if (!target.startsWith("/") || target.startsWith("//"))
        throw new HttpError(400, "invalid_request_target");
      const publicUrl = new URL(origin);
      const resolvedUrl = new URL(target, publicUrl);
      if (resolvedUrl.origin !== publicUrl.origin)
        throw new HttpError(400, "invalid_request_target");
      const url = resolvedUrl.toString();
      const fetchRequest = new Request(url, {
        method: request.method,
        headers: toHeaders(request),
        body: body && body.length > 0 ? new Uint8Array(body) : null,
      });
      const result = await handleApplicationRequest({
        request: fetchRequest,
        env,
        adapters,
      });
      await writeResponse(result, response);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      const code = error instanceof HttpError ? error.code : "internal_error";
      if (!response.headersSent) {
        response.writeHead(status, { "Content-Type": "application/json" });
      }
      response.end(JSON.stringify({ error: code }));
    }
  }
}

async function writeResponse(
  result: Response,
  response: ServerResponse,
): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  result.headers.forEach((value, name) => {
    headers[name] = value;
  });
  const setCookies = result.headers.getSetCookie();
  if (setCookies.length > 0) headers["set-cookie"] = setCookies;
  // Node's http server manages these itself.
  delete headers["transfer-encoding"];
  delete headers["content-length"];
  response.writeHead(result.status, headers);
  if (result.body === null) {
    response.end();
    return;
  }
  const buffer = Buffer.from(await result.arrayBuffer());
  response.end(buffer);
}
