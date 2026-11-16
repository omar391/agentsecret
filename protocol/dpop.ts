import {
  compactVerify,
  importJWK,
  calculateJwkThumbprint,
  SignJWT,
  exportJWK,
} from "jose";
import type { Proof } from "./proof-types";
import { HttpError, hash, now, random } from "../src/security/primitives";
export function target(uri: string): string {
  const url = new URL(uri);
  return url.origin + url.pathname;
}
/** Cryptographic validation only. The tenant authority atomically records replay IDs with the authorized operation. */
export async function verifyProof(
  request: Request,
  accessToken?: string,
  requestHash?: string,
  headerName = "DPoP",
): Promise<Proof> {
  const jwt = request.headers.get(headerName);
  if (!jwt || jwt.length > 8192)
    throw new HttpError(accessToken ? 401 : 400, "invalid_dpop_proof");
  try {
    const header = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(
          atob(jwt.split(".")[0].replace(/-/g, "+").replace(/_/g, "/")),
          (c) => c.charCodeAt(0),
        ),
      ),
    );
    const jwk = header.jwk;
    if (
      header.typ !== "dpop+jwt" ||
      header.alg !== "ES256" ||
      !jwk ||
      jwk.kty !== "EC" ||
      jwk.crv !== "P-256" ||
      Object.hasOwn(jwk, "d") ||
      typeof jwk.x !== "string" ||
      typeof jwk.y !== "string"
    )
      throw new Error();
    const key = await importJWK(jwk, "ES256");
    const verified = await compactVerify(jwt, key, { algorithms: ["ES256"] });
    const payload = JSON.parse(new TextDecoder().decode(verified.payload));
    if (
      payload.htm !== request.method ||
      payload.htu !== target(request.url) ||
      !Number.isSafeInteger(payload.iat) ||
      payload.iat > now() + 60 ||
      payload.iat <= now() - 300 ||
      typeof payload.jti !== "string" ||
      payload.jti.length < 1 ||
      payload.jti.length > 128
    )
      throw new Error();
    if (accessToken && payload.ath !== (await hash(accessToken)))
      throw new Error();
    if (requestHash !== undefined && payload.rqh !== requestHash)
      throw new Error();
    return {
      jkt: await calculateJwkThumbprint(jwk),
      jti: payload.jti,
      expiresAt: payload.iat + 300,
      requestHash: requestHash || "",
    };
  } catch {
    throw new HttpError(accessToken ? 401 : 400, "invalid_dpop_proof");
  }
}
export async function signProof(
  pair: CryptoKeyPair,
  method: string,
  uri: string,
  accessToken?: string,
  requestHash?: string,
): Promise<string> {
  const publicKey = await exportJWK(pair.publicKey);
  const claims: Record<string, unknown> = { htm: method, htu: target(uri) };
  if (accessToken) claims.ath = await hash(accessToken);
  if (requestHash !== undefined) claims.rqh = requestHash;
  return new SignJWT(claims)
    .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: publicKey })
    .setIssuedAt()
    .setJti(random())
    .sign(pair.privateKey);
}
