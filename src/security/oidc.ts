import {
  decodeJwt,
  jwtVerify,
  createLocalJWKSet,
  type JSONWebKeySet,
} from "jose";
import type { Env, Session } from "../types";
import { authority } from "../state/authority-kernel";
import { verifyProof } from "../../protocol/dpop";
import {
  body,
  hash,
  HttpError,
  json,
  now,
  reference,
  tenantId,
} from "./primitives";
import { providerJson } from "../bitwarden/client";
interface Trust {
  issuer: string;
  subject: string;
  audience: string;
  tenant: string;
  ref: string;
  repositoryId?: string;
  scopes: string[];
  aliases: string[];
  maxTtlSeconds?: number;
}
export async function federate(request: Request, env: Env): Promise<Response> {
  const input = await body(request);
  const assertion = input.oidc_token;
  if (typeof assertion !== "string" || assertion.length > 16384)
    throw new HttpError(400, "invalid_assertion");
  const proof = await verifyProof(request);
  let rules: Trust[];
  try {
    rules = JSON.parse(env.WORKLOAD_TRUST || "[]");
    if (!Array.isArray(rules)) throw new Error();
  } catch {
    throw new HttpError(503, "workload_trust_unconfigured");
  }
  let untrusted: ReturnType<typeof decodeJwt>;
  try {
    untrusted = decodeJwt(assertion);
  } catch {
    throw new HttpError(401, "invalid_assertion");
  }
  const rule = rules.find(
    (rule) =>
      rule.issuer === untrusted.iss &&
      rule.subject === untrusted.sub &&
      rule.ref === untrusted.ref,
  );
  if (
    !rule ||
    ![
      "https://token.actions.githubusercontent.com",
      "https://gitlab.com",
    ].includes(rule.issuer) ||
    rule.audience !== (env.PUBLIC_ORIGIN || new URL(request.url).origin)
  )
    throw new HttpError(403, "workload_not_trusted");
  const tenant = tenantId(rule.tenant);
  if (
    !Array.isArray(rule.aliases) ||
    !Array.isArray(rule.scopes) ||
    rule.scopes.some(
      (scope) =>
        !["secrets:proxy", "secrets:read", "secrets:write"].includes(scope),
    )
  )
    throw new HttpError(503, "invalid_workload_trust");
  const jwksUrl =
    rule.issuer === "https://token.actions.githubusercontent.com"
      ? rule.issuer + "/.well-known/jwks"
      : rule.issuer + "/oauth/discovery/keys";
  const jwks = await providerJson(jwksUrl, {});
  let payload;
  try {
    const verified = await jwtVerify(
      assertion,
      createLocalJWKSet(jwks as unknown as JSONWebKeySet),
      {
        issuer: rule.issuer,
        audience: rule.audience,
        algorithms: ["RS256"],
        requiredClaims: ["sub", "exp", "iat"],
        maxTokenAge: 900,
        clockTolerance: 0,
      },
    );
    payload = verified.payload;
    if (
      payload.sub !== rule.subject ||
      payload.ref !== rule.ref ||
      (rule.issuer === "https://token.actions.githubusercontent.com" &&
        (!rule.repositoryId || payload.repository_id !== rule.repositoryId)) ||
      !Number.isSafeInteger(payload.exp)
    )
      throw new Error();
  } catch {
    throw new HttpError(401, "invalid_assertion");
  }
  const ttl = Math.min(900, Math.max(60, rule.maxTtlSeconds || 900));
  const session: Session = {
    tenant,
    purpose: "agent",
    audience: rule.audience,
    agentId: await hash(
      JSON.stringify([
        rule.issuer,
        rule.subject,
        rule.ref,
        rule.repositoryId || "",
      ]),
    ),
    scopes: rule.scopes,
    aliases: rule.aliases.map((alias) => alias.toUpperCase()),
    jkt: proof.jkt,
    exp: Math.min(now() + ttl, payload.exp!),
    epoch: 0,
  };
  if (session.exp <= now()) throw new HttpError(401, "expired_assertion");
  const token = reference("as2", tenant);
  await authority(env, tenant, {
    op: "federate",
    session,
    proof,
    assertionHash: await hash(rule.issuer + ":" + assertion),
    assertionExp: payload.exp,
    tokenHash: await hash(token),
  });
  return json({
    access_token: token,
    token_type: "DPoP",
    scope: session.scopes.join(" "),
    expires_in: session.exp - now(),
  });
}
