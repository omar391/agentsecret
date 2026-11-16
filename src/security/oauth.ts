import type {
  Env,
  Grant,
  Principal,
  SecretPolicy,
  Session,
  VaultConnection,
} from "../types";
import { authority } from "../state/authority-kernel";
import { control, sameOrigin } from "./auth";
import { requireCustomerSession } from "../auth/sessions";
import { findAccountById } from "../registry/store";
import { verifyProof } from "../../protocol/dpop";
import {
  body,
  escape,
  hash,
  html,
  HttpError,
  json,
  now,
  random,
  reference,
  referenceTenant,
  tenantId,
} from "./primitives";

function credentialSink(policy: SecretPolicy): string {
  if (policy.injectionType === "header")
    return `header ${policy.headerName || ""}`;
  if (policy.injectionType === "query_param")
    return `query parameter ${policy.queryParamName || ""}`;
  if (policy.injectionType === "body_placeholder")
    return "one {{AGENTSECRET_SECRET}} request-body placeholder";
  return policy.injectionType;
}

export function validateClient(env: Env, clientId: string, redirect: string) {
  let url: URL;
  try {
    url = new URL(redirect);
  } catch {
    throw new HttpError(400, "invalid_redirect_uri");
  }
  if (url.username || url.password || url.hash)
    throw new HttpError(400, "invalid_redirect_uri");
  if (
    clientId === "agentsecret-cli" &&
    url.protocol === "http:" &&
    url.hostname === "127.0.0.1" &&
    url.pathname === "/callback" &&
    !url.search &&
    !!url.port
  )
    return;
  let clients: Record<string, { redirectUris: string[] }> = {};
  try {
    clients = JSON.parse(env.OAUTH_CLIENTS || "{}");
  } catch {
    throw new HttpError(503, "oauth_clients_unconfigured");
  }
  if (
    url.protocol !== "https:" ||
    !clients[clientId]?.redirectUris?.includes(redirect)
  )
    throw new HttpError(400, "invalid_redirect_uri");
}
export async function authorize(
  request: Request,
  env: Env,
  url: URL,
): Promise<Response> {
  const clientId = url.searchParams.get("client_id") || "";
  const redirectUri = url.searchParams.get("redirect_uri") || "";
  const challenge = url.searchParams.get("code_challenge") || "";
  const state = url.searchParams.get("state") || "";
  if (
    url.searchParams.get("response_type") !== "code" ||
    url.searchParams.get("code_challenge_method") !== "S256" ||
    !/^[\w-]{43}$/.test(challenge) ||
    !state ||
    state.length > 512
  )
    throw new HttpError(400, "invalid_authorization_request");
  validateClient(env, clientId, redirectUri);
  if (request.method !== "GET" && request.method !== "POST")
    throw new HttpError(405, "method_not_allowed");
  let principal: Principal;
  try {
    principal = await control(request, env);
  } catch (error) {
    // A browser that reaches the consent page without a session is sent to customer sign-in;
    // there is no shared-password browser fallback. The workload credential remains available
    // through its Authorization: Bearer path until workload federation lands.
    if (request.method === "GET")
      return new Response(null, {
        status: 303,
        headers: { Location: "/?view=dashboard", "Cache-Control": "no-store" },
      });
    // Do not turn a body field into a workload credential. That would make the shared
    // MCP_AUTH_TOKEN a browser password again. Agent clients authenticate with Bearer directly.
    throw new HttpError(401, "unauthorized");
  }
  requireCustomerSession(principal);
  const requestDigest = await hash(
    JSON.stringify([
      url.searchParams.get("response_type"),
      clientId,
      redirectUri,
      challenge,
      url.searchParams.get("code_challenge_method"),
      state,
      url.searchParams.get("scope") || "secrets:proxy secrets:read",
      url.searchParams.get("aliases") || "",
    ]),
  );
  const requested = (
    url.searchParams.get("scope") || "secrets:proxy secrets:read"
  )
    .split(" ")
    .filter(Boolean);
  if (
    !requested.length ||
    requested.some(
      (scope) =>
        !["secrets:proxy", "secrets:read", "secrets:write"].includes(scope),
    )
  )
    throw new HttpError(400, "invalid_scope");
  const scopes = requested.filter(
    (scope) =>
      principal.scopes.includes(scope) || principal.scopes.includes("admin"),
  );
  if (!scopes.length) throw new HttpError(403, "insufficient_scope");
  if (requested.includes("secrets:write") && !scopes.includes("secrets:write"))
    throw new HttpError(403, "insufficient_scope");
  const submitted =
    request.method === "POST"
      ? await body(request.clone() as unknown as Request)
      : {};
  const parseAliases = (value: unknown) =>
    String(value || "")
      .split(",")
      .map((alias) => alias.trim().toUpperCase())
      .filter(Boolean);
  const clientRequestedAliases = parseAliases(url.searchParams.get("aliases"));
  const requestedAliases = parseAliases(
    submitted.aliases ?? url.searchParams.get("aliases"),
  );
  if (
    requestedAliases.length > 30 ||
    clientRequestedAliases.length > 30 ||
    [...requestedAliases, ...clientRequestedAliases].some(
      (alias) => !/^[A-Z][A-Z0-9_]{0,63}$/.test(alias),
    ) ||
    (clientRequestedAliases.length > 0 &&
      requestedAliases.some((alias) => !clientRequestedAliases.includes(alias)))
  )
    throw new HttpError(400, "invalid_alias_grant");
  const aliases = [...new Set(requestedAliases)].filter(
    (alias) =>
      principal.aliases === undefined || principal.aliases.includes(alias),
  );
  if (aliases.length !== new Set(requestedAliases).size)
    throw new HttpError(400, "invalid_alias_grant");
  const code = reference("ac2", principal.tenant);
  if (request.method === "GET") {
    const consentId = random(24);
    const [reviewed, account] = await Promise.all([
      authority<{
        aliases: string[];
        policies: SecretPolicy[];
        connections: VaultConnection[];
      }>(env, principal.tenant, {
        op: "create_consent",
        principal,
        key: consentId,
        ...(clientRequestedAliases.length
          ? { aliases: clientRequestedAliases }
          : {}),
        clientId,
        scopes,
        requestDigest,
      }),
      env.DB
        ? findAccountById(env.DB, principal.tenant)
        : Promise.resolve(null),
    ]);
    const showing = reviewed.policies;
    const connections = reviewed.connections;
    const connectionLabel = (id?: string) => {
      const connection = connections.find((item) => item.id === id);
      return connection
        ? `${connection.alias} (${connection.provider})`
        : "legacy default vault";
    };
    const policyRows = showing.length
      ? showing
          .map(
            (policy) =>
              `<li><strong>${escape(policy.alias)}</strong> — ${escape(policy.description)}; destination: ${escape(policy.allowedDomains.join(", "))}; methods: ${escape(policy.allowedMethods.join(", "))}; credential sink: ${escape(credentialSink(policy))}; connection: ${escape(connectionLabel(policy.connectionId))}${scopes.includes("secrets:write") ? `; owner write grant: create ${policy.secretWrite?.create ? "yes" : "no"}, update ${policy.secretWrite?.update ? "yes" : "no"}, delete ${policy.secretWrite?.delete ? "yes" : "no"}` : ""}</li>`,
          )
          .join("")
      : "<li>No currently configured aliases</li>";
    const initialAliases =
      url.searchParams.get("aliases") || showing.map((p) => p.alias).join(",");
    return html(
      `<h1>Authorize ${escape(clientId)}</h1><p>Account: ${escape(account?.name || principal.tenant)}</p><p>Operation profile: HTTP secret proxy. Scopes: ${escape(scopes.join(", "))}. Expires within one hour and no later than this sign-in session.</p><p>Review each alias, destination, method, credential sink, and vault connection. Secret write is limited to the separately approved create, update, and delete actions shown for each alias. Editing a policy later requires fresh agent consent.</p><ul>${policyRows}</ul><form method="post" action="${escape(url.pathname + url.search)}"><input type="hidden" name="consent_id" value="${escape(consentId)}"><label>Approved aliases (comma separated) <input name="aliases" value="${escape(initialAliases)}" autocomplete="off"></label><button>Authorize client</button></form>`,
    );
  }
  sameOrigin(request, true);
  const grant: Grant = {
    kind: "code",
    status: "approved",
    audience: env.PUBLIC_ORIGIN || url.origin,
    exp: Math.min(now() + 300, principal.exp),
    sessionExp: Math.min(now() + 3600, principal.exp),
    clientId,
    redirectUri,
    challenge,
    scopes,
    aliases,
    parent: principal.bootstrap ? undefined : principal.hash,
    epoch: principal.epoch,
  };
  await authority(env, principal.tenant, {
    op: "put_grant",
    principal,
    hash: await hash(code),
    grant,
    consentKey: String(submitted.consent_id || ""),
    requestDigest,
  });
  const target = new URL(redirectUri);
  target.searchParams.set("code", code);
  target.searchParams.set("state", state);
  return new Response(null, {
    status: 302,
    headers: {
      Location: target.toString(),
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}
export async function token(request: Request, env: Env): Promise<Response> {
  const input = await body(request);
  const type = input.grant_type;
  if (
    type !== "authorization_code" &&
    type !== "urn:ietf:params:oauth:grant-type:device_code"
  )
    throw new HttpError(400, "unsupported_grant_type");
  const raw = String(
    type === "authorization_code" ? input.code || "" : input.device_code || "",
  );
  const tenant = referenceTenant(
    raw,
    type === "authorization_code" ? "ac2" : "dc2",
  );
  const digest = await hash(raw);
  const grant = await authority<Grant | null>(env, tenant, {
    op: "peek_grant",
    hash: digest,
  });
  if (
    !grant ||
    grant.exp <= now() ||
    grant.audience !== (env.PUBLIC_ORIGIN || new URL(request.url).origin)
  )
    throw new HttpError(400, "invalid_grant");
  const proof = await verifyProof(request);
  if (grant.jkt && grant.jkt !== proof.jkt)
    throw new HttpError(400, "invalid_dpop_proof");
  if (type === "authorization_code") {
    const verifier = input.code_verifier;
    if (
      grant.kind !== "code" ||
      typeof verifier !== "string" ||
      !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
      input.client_id !== grant.clientId ||
      input.redirect_uri !== grant.redirectUri ||
      (await hash(verifier)) !== grant.challenge
    )
      throw new HttpError(400, "invalid_grant");
  } else {
    if (grant.kind !== "device" || input.client_id !== grant.clientId)
      throw new HttpError(400, "invalid_grant");
    if (grant.status === "pending") {
      const error = await authority<string>(env, tenant, {
        op: "poll",
        hash: digest,
        proof,
      });
      return json({ error }, 400);
    }
  }
  const accessToken = reference("as2", tenant);
  const session: Session = {
    tenant,
    purpose: "agent",
    audience: grant.audience,
    scopes: grant.scopes,
    aliases: grant.aliases,
    jkt: proof.jkt,
    exp: Math.min(now() + 3600, grant.sessionExp || grant.exp),
    epoch: grant.epoch,
  };
  const issued = await authority<Session>(env, tenant, {
    op: "redeem",
    hash: digest,
    expected: JSON.stringify(grant),
    proof,
    tokenHash: await hash(accessToken),
    session,
  });
  return json({
    access_token: accessToken,
    token_type: "DPoP",
    expires_in: issued.exp - now(),
    scope: issued.scopes.join(" "),
    assigned_aliases: issued.aliases,
  });
}
export async function deviceCode(
  request: Request,
  env: Env,
): Promise<Response> {
  const input = await body(request);
  const tenant = tenantId(input.tenant || "default");
  const proof = await verifyProof(request);
  await authority(env, tenant, {
    op: "rate",
    key:
      "device:" +
      (await hash(request.headers.get("CF-Connecting-IP") || "local")),
    limit: 10,
  });
  if (input.client_id !== "agentsecret-cli")
    throw new HttpError(400, "invalid_client");
  const requestedScopes = Array.isArray(input.scope)
    ? input.scope
    : String(input.scope || "secrets:proxy secrets:read")
        .split(" ")
        .filter(Boolean);
  if (
    !requestedScopes.length ||
    requestedScopes.some(
      (scope) =>
        !["secrets:proxy", "secrets:read", "secrets:write"].includes(scope),
    )
  )
    throw new HttpError(400, "invalid_scope");
  const code = reference("dc2", tenant);
  const userCode = random(9).toUpperCase();
  const aliases = Array.isArray(input.aliases) ? input.aliases : [];
  if (
    aliases.length > 30 ||
    aliases.some(
      (alias) =>
        typeof alias !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(alias),
    )
  )
    throw new HttpError(400, "invalid_alias_grant");
  const grant: Grant = {
    kind: "device",
    status: "pending",
    audience: env.PUBLIC_ORIGIN || new URL(request.url).origin,
    exp: now() + 600,
    clientId: "agentsecret-cli",
    jkt: proof.jkt,
    userCode,
    aliases: aliases as string[],
    scopes: [],
    requestedScopes: [...new Set(requestedScopes)],
    epoch: 0,
  };
  await authority(env, tenant, {
    op: "put_grant",
    hash: await hash(code),
    grant,
    proof,
  });
  const origin = env.PUBLIC_ORIGIN || new URL(request.url).origin;
  return json({
    device_code: code,
    user_code: userCode,
    verification_uri: origin + "/device",
    verification_uri_complete:
      origin + "/device?tenant=" + tenant + "&code=" + userCode,
    expires_in: 600,
    interval: 5,
  });
}
export async function approveDevice(
  request: Request,
  env: Env,
  authenticatedPrincipal?: Principal,
): Promise<Response> {
  const principal = authenticatedPrincipal ?? (await control(request, env));
  // Only a real customer session may approve a device. `control` alone would admit the workload
  // bootstrap credential (whose tenant owns no device codes), so the customer guard is what makes
  // "approvals work for a signed-in customer and for nobody else" an enforced property.
  requireCustomerSession(principal);
  const input = await body(request);
  if (
    typeof input.user_code !== "string" ||
    !/^[A-Z0-9_-]{12}$/.test(input.user_code)
  )
    throw new HttpError(400, "invalid_user_code");
  const aliases = String(input.aliases || "")
    .split(",")
    .map((item: string) => item.trim())
    .filter(Boolean);
  if (
    aliases.length > 30 ||
    aliases.some((alias: string) => !/^[A-Z][A-Z0-9_]{0,63}$/.test(alias))
  )
    throw new HttpError(400, "invalid_alias_grant");
  await authority(env, principal.tenant, {
    op: "approve_device",
    principal,
    userCode: input.user_code,
    aliases,
    consentKey: input.consent_id,
  });
  return json({ success: true });
}

export async function deviceReview(
  request: Request,
  env: Env,
  principal?: Principal,
): Promise<Response> {
  const session = principal ?? (await control(request, env));
  requireCustomerSession(session);
  const url = new URL(request.url);
  const userCode = url.searchParams.get("code") || "";
  if (!/^[A-Z0-9_-]{12}$/.test(userCode))
    throw new HttpError(400, "invalid_user_code");
  const consentId = random(24);
  const reviewed = await authority<any>(env, session.tenant, {
    op: "device_review",
    principal: session,
    userCode,
    consentKey: consentId,
  });
  const account = env.DB ? await findAccountById(env.DB, session.tenant) : null;
  const connectionLabel = (id?: string) => {
    const connection = reviewed.connections.find(
      (item: VaultConnection) => item.id === id,
    );
    return connection
      ? `${connection.alias} (${connection.provider})`
      : "legacy default vault";
  };
  const requestedScopes = reviewed.grant.requestedScopes || [
    "secrets:proxy",
    "secrets:read",
  ];
  const rows = reviewed.policies
    .map(
      (policy: SecretPolicy) =>
        `<li><strong>${escape(policy.alias)}</strong> — ${escape(policy.description)}; destinations: ${escape(policy.allowedDomains.join(", "))}; methods: ${escape(policy.allowedMethods.join(", "))}; credential sink: ${escape(credentialSink(policy))}; connection: ${escape(connectionLabel(policy.connectionId))}${requestedScopes.includes("secrets:write") ? `; owner write grant: create ${policy.secretWrite?.create ? "yes" : "no"}, update ${policy.secretWrite?.update ? "yes" : "no"}, delete ${policy.secretWrite?.delete ? "yes" : "no"}` : ""}</li>`,
    )
    .join("");
  const selectableAliases = reviewed.policies
    .map((policy: SecretPolicy) => policy.alias)
    .filter((alias: string) => (reviewed.grant.aliases || []).includes(alias));
  const form = `<h1>Review device access</h1><p>Account: ${escape(account?.name || session.tenant)}</p><p>Client: ${escape(reviewed.grant.clientId)}. Requested scopes: ${escape(requestedScopes.join(", "))}. access expires ${new Date(reviewed.sessionExp * 1000).toISOString()}. Approval code expires ${new Date(reviewed.grant.exp * 1000).toISOString()}.</p><ul>${rows || "<li>No configured aliases are eligible for the requested scopes</li>"}</ul><form method="post" action="/device"><input type="hidden" name="user_code" value="${escape(userCode)}"><input type="hidden" name="consent_id" value="${escape(consentId)}"><label>Approved aliases (comma separated) <input name="aliases" value="${escape(selectableAliases.join(","))}"></label><button>Approve selected access</button></form>`;
  return html(form);
}
