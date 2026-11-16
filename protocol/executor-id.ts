import { calculateJwkThumbprint } from "jose";

function encodeBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");
}

/** Accept only a public P-256 JWK; private or malformed keys fail closed. */
export function validateExecutorJwk(value: unknown): JsonWebKey {
  if (!value || typeof value !== "object")
    throw new Error("executor_jwk_invalid");
  const jwk = value as JsonWebKey;
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    jwk.x.length > 128 ||
    jwk.y.length > 128 ||
    Object.hasOwn(jwk, "d")
  )
    throw new Error("executor_jwk_invalid");
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

export async function executorIdForJwk(publicJwk: JsonWebKey): Promise<string> {
  const jwk = validateExecutorJwk(publicJwk);
  const thumbprint = await calculateJwkThumbprint(jwk);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(thumbprint),
  );
  return "exe_" + encodeBase64Url(new Uint8Array(digest));
}

export async function executorThumbprint(
  publicJwk: JsonWebKey,
): Promise<string> {
  return calculateJwkThumbprint(validateExecutorJwk(publicJwk));
}
