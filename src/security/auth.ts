import type { Env, Principal, Session, Proof } from "../types";
import { authority } from "../state/authority-kernel";
import { equal, hash, now, referenceTenant, HttpError } from "./primitives";
import { verifyProof } from "../../protocol/dpop";
export function sameOrigin(request: Request, required = false) {
  const origin = request.headers.get("Origin");
  if (
    (required && !origin) ||
    (origin && origin !== new URL(request.url).origin)
  )
    throw new HttpError(403, "origin_denied");
}
export async function authenticate(
  request: Request,
  env: Env,
  consumeProof = false,
  requestHash?: string,
): Promise<{ principal: Principal; proof?: Proof }> {
  const authorization = request.headers.get("Authorization");
  const cookie = request.headers
    .get("Cookie")
    ?.split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith("agentsecret_session="))
    ?.slice("agentsecret_session=".length);
  const bearer = authorization?.match(/^(Bearer|DPoP) ([A-Za-z0-9._-]+)$/)?.[2];
  // An Authorization header is an explicit credential choice. Reject malformed values
  // instead of silently falling back to a cookie and bypassing cookie CSRF checks.
  if (authorization && !bearer) throw new HttpError(401, "unauthorized");
  const token = bearer || cookie;
  if (!token) throw new HttpError(401, "unauthorized");
  if (
    env.MCP_AUTH_TOKEN &&
    env.MCP_AUTH_TOKEN.length >= 32 &&
    equal(token, env.MCP_AUTH_TOKEN)
  ) {
    if (!authorization) throw new HttpError(401, "unauthorized");
    return {
      principal: {
        tenant: "default",
        purpose: "control",
        audience: env.PUBLIC_ORIGIN || new URL(request.url).origin,
        scopes: ["admin", "operator:tenants", "secrets:read", "secrets:proxy"],
        exp: now() + 3600,
        epoch: 0,
        hash: "bootstrap",
        bootstrap: true,
      },
    };
  }
  const tenant = referenceTenant(token, "as2");
  const digest = await hash(token);
  const stored = await authority<Session | null>(env, tenant, {
    op: "get_session",
    hash: digest,
  });
  if (
    !stored ||
    stored.tenant !== tenant ||
    stored.audience !== (env.PUBLIC_ORIGIN || new URL(request.url).origin) ||
    stored.exp <= now()
  )
    throw new HttpError(401, "invalid_token");
  if (stored.purpose === "control") {
    if (
      !authorization &&
      request.method !== "GET" &&
      request.method !== "HEAD"
    ) {
      sameOrigin(request, true);
      // `Sec-Fetch-Site` is set by the browser and cannot be forged by page script, so a
      // cookie-authenticated mutation is refused cross-site even if the request carried a
      // same-origin `Origin` header (which only a non-browser client can produce). This is a
      // second, independent check rather than a replacement: the origin gate above is what a
      // browser actually enforces, this one also covers a caller that fabricates headers.
      if (request.headers.get("Sec-Fetch-Site") === "cross-site")
        throw new HttpError(403, "origin_denied");
    } else sameOrigin(request);
  }
  const proof =
    stored.purpose === "agent"
      ? await verifyProof(request, token, requestHash)
      : undefined;
  const principal = { ...stored, hash: digest };
  await authority(env, tenant, {
    op: "authenticate",
    principal,
    proof,
    consumeProof,
  });
  return { principal, proof };
}
export async function control(request: Request, env: Env): Promise<Principal> {
  const { principal } = await authenticate(request, env);
  if (principal.purpose !== "control" || !principal.scopes.includes("admin"))
    throw new HttpError(403, "control_session_required");
  return principal;
}
