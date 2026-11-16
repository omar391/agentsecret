import type {
  BackgroundContext,
  Env,
  Principal,
  Proof,
  ProxyRequestParams,
  SecretPolicy,
} from "./types";
import { SECRET_BODY_PLACEHOLDER } from "./constants";
import { authority } from "./state/authority-kernel";
import type { Envelope } from "./vaults/encryption";
import type { VaultConnection } from "./types";
import { resolveSecret } from "./vaults/manager";
import { hash, HttpError, readText, random } from "./security/primitives";
import {
  sanitizeResponseHeaders,
  scrubSecretsFromPayload,
} from "./security/sanitizer";
import { isSsrfTarget } from "./security/policy";
import { pinnedFetch } from "./security/pinned-fetch";

const UNSUPPORTED_TRANSPORT_HEADERS =
  /^(connection|keep-alive|proxy-connection|proxy-authenticate|te|trailer|upgrade|expect)$/i;
const HTTP_FIELD_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/;
const BROKER_CONTROLLED_ENCODING_HEADERS =
  /^(accept-encoding|content-encoding)$/i;
function isSupportedHeaderValue(value: string): boolean {
  if (
    value !== value.trim() ||
    /[\u0000-\u0008\u000a-\u001f\u007f]/.test(value)
  )
    return false;
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined || codePoint > 0x7e) return false;
  }
  return true;
}

export function validatePolicy(input: unknown): SecretPolicy {
  const p = input as SecretPolicy;
  if (
    !p ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(p.alias) ||
    typeof p.description !== "string" ||
    p.description.length > 512 ||
    !Array.isArray(p.allowedDomains) ||
    !p.allowedDomains.length ||
    p.allowedDomains.length > 20 ||
    !Array.isArray(p.allowedMethods) ||
    !p.allowedMethods.length ||
    p.allowedMethods.some(
      (method) =>
        !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(
          method,
        ),
    ) ||
    !["bearer", "header", "basic", "query_param", "body_placeholder"].includes(
      p.injectionType,
    )
  )
    throw new HttpError(400, "invalid_policy");
  for (const domain of p.allowedDomains) {
    if (
      typeof domain !== "string" ||
      domain.length > 253 ||
      !/^([a-z0-9-]+\.)+[a-z0-9-]+$/i.test(domain.replace(/^\*\./, "")) ||
      isSsrfTarget(domain.replace(/^\*\./, ""))
    )
      throw new HttpError(400, "invalid_policy_domain");
  }
  if (
    p.pathPatterns &&
    (!Array.isArray(p.pathPatterns) ||
      p.pathPatterns.length > 20 ||
      p.pathPatterns.some(
        (pattern) =>
          typeof pattern !== "string" ||
          pattern.length > 256 ||
          !/^!?\//.test(pattern),
      ))
  )
    throw new HttpError(400, "invalid_path_policy");
  if (
    p.headerName &&
    (!HTTP_FIELD_NAME.test(p.headerName) ||
      UNSUPPORTED_TRANSPORT_HEADERS.test(p.headerName) ||
      BROKER_CONTROLLED_ENCODING_HEADERS.test(p.headerName) ||
      /^(host|connection|content-length|transfer-encoding|cookie|proxy-authorization)$/i.test(
        p.headerName,
      ))
  )
    throw new HttpError(400, "invalid_auth_header");
  if (p.injectionType === "header" && !p.headerName)
    throw new HttpError(400, "auth_header_required");
  if (
    p.injectionType === "query_param" &&
    !/^[A-Za-z0-9_-]{1,80}$/.test(p.queryParamName || "")
  )
    throw new HttpError(400, "invalid_auth_parameter");
  if (p.secretId && (typeof p.secretId !== "string" || p.secretId.length > 256))
    throw new HttpError(400, "invalid_secret_reference");
  if (
    p.connectionId &&
    (typeof p.connectionId !== "string" ||
      !/^[A-Za-z0-9_-]{20,64}$/.test(p.connectionId))
  )
    throw new HttpError(400, "invalid_vault_connection");
  if (p.connectionId && !p.secretId)
    throw new HttpError(400, "explicit_secret_reference_required");
  if (p.findSelector !== undefined) {
    const selector = p.findSelector;
    const commonInvalid =
      !selector ||
      typeof selector !== "object" ||
      Array.isArray(selector) ||
      typeof selector.title !== "string" ||
      !selector.title.trim() ||
      selector.title.length > 128 ||
      /[\u0000-\u001f\u007f]/.test(selector.title);
    const legacyInvalid =
      selector?.kind === undefined &&
      (Object.keys(selector || {}).some(
        (key) => key !== "title" && key !== "fieldId",
      ) ||
        (selector?.fieldId !== undefined &&
          (typeof selector.fieldId !== "string" ||
            !selector.fieldId ||
            selector.fieldId.length > 256 ||
            /[\u0000-\u001f\u007f]/.test(selector.fieldId))));
    const loginInvalid =
      selector?.kind === "login_lookup" &&
      (Object.keys(selector).some(
        (key) =>
          ![
            "kind",
            "title",
            "username",
            "uris",
            "fieldId",
            "fieldPath",
          ].includes(key),
      ) ||
        typeof selector.username !== "string" ||
        !selector.username.trim() ||
        selector.username.length > 512 ||
        /[\u0000-\u001f\u007f]/.test(selector.username) ||
        !Array.isArray(selector.uris) ||
        selector.uris.length < 1 ||
        selector.uris.length > 16 ||
        selector.uris.some(
          (uri) =>
            typeof uri !== "string" ||
            !uri.trim() ||
            uri.length > 2048 ||
            /[\u0000-\u001f\u007f]/.test(uri),
        ) ||
        new Set(selector.uris).size !== selector.uris.length ||
        typeof selector.fieldId !== "string" ||
        !selector.fieldId.trim() ||
        selector.fieldId.length > 256 ||
        /[\u0000-\u001f\u007f]/.test(selector.fieldId) ||
        (selector.fieldPath !== undefined &&
          (typeof selector.fieldPath !== "string" ||
            !selector.fieldPath.trim() ||
            selector.fieldPath.length > 256 ||
            /[\u0000-\u001f\u007f]/.test(selector.fieldPath))));
    if (
      commonInvalid ||
      (selector.kind !== undefined && selector.kind !== "login_lookup") ||
      (selector.kind === undefined ? legacyInvalid : loginInvalid) ||
      !p.connectionId ||
      !p.secretId
    )
      throw new HttpError(400, "invalid_find_selector");
  }
  if (
    p.secretWrite !== undefined &&
    (!p.secretWrite ||
      typeof p.secretWrite !== "object" ||
      Array.isArray(p.secretWrite) ||
      Object.keys(p.secretWrite).some(
        (key) => key !== "create" && key !== "update" && key !== "delete",
      ) ||
      Object.values(p.secretWrite).some(
        (value) => typeof value !== "boolean",
      ) ||
      (!p.secretWrite.create &&
        !p.secretWrite.update &&
        !p.secretWrite.delete) ||
      !p.connectionId ||
      !p.secretId)
  )
    throw new HttpError(400, "invalid_secret_write_policy");
  return {
    alias: p.alias,
    description: p.description,
    allowedDomains: p.allowedDomains.map((domain) => domain.toLowerCase()),
    allowedMethods: p.allowedMethods,
    pathPatterns: p.pathPatterns,
    injectionType: p.injectionType,
    headerName: p.headerName,
    username: p.username,
    queryParamName: p.queryParamName,
    secretId: p.secretId,
    connectionId: p.connectionId,
    findSelector: p.findSelector,
    secretWrite: p.secretWrite,
  };
}
export function normalize(input: unknown): ProxyRequestParams {
  const p = input as ProxyRequestParams;
  if (
    !p ||
    typeof p.secret_alias !== "string" ||
    !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(p.secret_alias) ||
    typeof p.url !== "string" ||
    p.url.length > 4096 ||
    (p.method !== undefined && typeof p.method !== "string")
  )
    throw new HttpError(400, "invalid_proxy_request");
  let url: URL;
  try {
    url = new URL(p.url);
  } catch {
    throw new HttpError(400, "invalid_url");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    (url.port && url.port !== "443") ||
    isSsrfTarget(url.hostname) ||
    /%(2f|5c|2e|25)/i.test(url.pathname)
  )
    throw new HttpError(403, "unsafe_target");
  if (
    p.headers &&
    (typeof p.headers !== "object" ||
      Array.isArray(p.headers) ||
      Object.keys(p.headers).length > 32 ||
      Object.entries(p.headers).some(
        ([key, value]) =>
          typeof value !== "string" ||
          value.length > 4096 ||
          !HTTP_FIELD_NAME.test(key) ||
          !isSupportedHeaderValue(value) ||
          UNSUPPORTED_TRANSPORT_HEADERS.test(key) ||
          /^(authorization|proxy-authorization|cookie|host|connection|content-length|transfer-encoding|forwarded|x-forwarded-.*|cf-.*|sec-.*|x-api-key|api-key)$/i.test(
            key,
          ),
      ))
  )
    throw new HttpError(400, "invalid_headers");
  if (
    p.headers &&
    Object.keys(p.headers).some((key) => /^accept-encoding$/i.test(key))
  )
    throw new HttpError(400, "unsupported_http_encoding");
  if (
    p.headers &&
    Object.entries(p.headers).some(
      ([key, value]) =>
        /^content-encoding$/i.test(key) && !/^identity$/i.test(value),
    )
  )
    throw new HttpError(400, "unsupported_http_encoding");
  const method = (p.method || "GET").toUpperCase();
  if (
    !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(
      method,
    ) ||
    (["GET", "HEAD"].includes(method) && p.body !== undefined)
  )
    throw new HttpError(400, "invalid_method");
  return {
    secret_alias: p.secret_alias.toUpperCase(),
    url: url.toString(),
    method,
    headers: p.headers,
    body: p.body,
  };
}
export async function execute(
  input: unknown,
  principal: Principal,
  proof: Proof | undefined,
  requestHash: string,
  env: Env,
  ctx: BackgroundContext,
) {
  const params = normalize(input);
  const authorized = await authority<{
    policy: SecretPolicy;
    vault: Envelope | null;
    connection?: (VaultConnection & { envelope: Envelope }) | null;
  }>(env, principal.tenant, {
    op: "execute",
    principal,
    proof,
    requestHash,
    alias: params.secret_alias,
    url: params.url,
    method: params.method,
  });
  return executeAuthorized(params, authorized, principal, env, ctx);
}

export async function executeCapability(
  input: unknown,
  capability: string,
  env: Env,
  ctx: BackgroundContext,
) {
  const params = normalize(input);
  const match = /^aspc1\.([A-Za-z0-9_-]{1,80})\.[A-Za-z0-9_-]{32,128}$/.exec(
    capability,
  );
  if (!match) throw new HttpError(401, "invalid_proxy_capability");
  const authorized = await authority<{
    policy: SecretPolicy;
    vault: Envelope | null;
    connection?: (VaultConnection & { envelope: Envelope }) | null;
    principal: Principal;
  }>(env, match[1], {
    op: "execute_proxy_capability",
    capabilityHash: await hash(capability),
    requestDigest: await hash(JSON.stringify(params)),
  });
  return executeAuthorized(params, authorized, authorized.principal, env, ctx);
}

async function executeAuthorized(
  params: ProxyRequestParams,
  authorized: {
    policy: SecretPolicy;
    vault: Envelope | null;
    connection?: (VaultConnection & { envelope: Envelope }) | null;
  },
  principal: Principal,
  env: Env,
  ctx: BackgroundContext,
) {
  if (
    authorized.policy.injectionType === "header" &&
    BROKER_CONTROLLED_ENCODING_HEADERS.test(authorized.policy.headerName || "")
  )
    throw new HttpError(409, "unsupported_credential_header");
  const secret = await resolveSecret(
    principal.tenant,
    authorized.policy,
    authorized.vault,
    env,
    authorized.connection || undefined,
  );
  if (!secret || secret.length > 8192 || /[\r\n]/.test(secret))
    throw new HttpError(502, "invalid_credential_value");
  const headers = new Headers();
  for (const [key, value] of Object.entries(params.headers || {})) {
    if (
      /^(authorization|proxy-authorization|cookie|host|connection|content-length|transfer-encoding|forwarded|x-forwarded-.*|cf-.*|sec-.*|x-api-key|api-key)$/i.test(
        key,
      ) ||
      UNSUPPORTED_TRANSPORT_HEADERS.test(key)
    )
      throw new HttpError(400, "reserved_header");
    headers.set(key, value);
  }
  const url = new URL(params.url);
  // Cloudflare Workers otherwise requests gzip/brotli from the origin by
  // default. Ask for identity so the response guard inspects the actual text.
  headers.set("Accept-Encoding", "identity");
  const redactionTargets = [secret];
  if (
    params.body !== undefined &&
    typeof params.body !== "string" &&
    !headers.has("Content-Type")
  )
    headers.set("Content-Type", "application/json");
  let outboundBody =
    params.body === undefined
      ? undefined
      : typeof params.body === "string"
        ? params.body
        : JSON.stringify(params.body);
  if (authorized.policy.injectionType === "body_placeholder") {
    if (typeof outboundBody !== "string")
      throw new HttpError(400, "secret_placeholder_required");
    const occurrences = outboundBody.split(SECRET_BODY_PLACEHOLDER).length - 1;
    if (occurrences !== 1)
      throw new HttpError(400, "secret_placeholder_required");
    outboundBody = substituteBodyPlaceholder(
      outboundBody,
      secret,
      headers.get("Content-Type") || "",
    );
  }
  switch (authorized.policy.injectionType) {
    case "bearer":
      headers.set("Authorization", "Bearer " + secret);
      break;
    case "header":
      headers.set(authorized.policy.headerName!, secret);
      break;
    case "basic": {
      const payload = btoa(
        String.fromCharCode(
          ...new TextEncoder().encode(
            (authorized.policy.username || "") + ":" + secret,
          ),
        ),
      );
      const credential = "Basic " + payload;
      redactionTargets.push(credential, payload);
      headers.set("Authorization", credential);
      break;
    }
    case "query_param": {
      const name = authorized.policy.queryParamName!;
      url.searchParams.set(name, secret);
      // Capture the actual form encoding sent upstream, including space-to-plus
      // conversion and punctuation escaping, rather than encodeURIComponent.
      const field = url.searchParams
        .toString()
        .split("&")
        .find((part) => part.startsWith(name + "="))!;
      redactionTargets.push(field.slice(name.length + 1));
      break;
    }
    case "body_placeholder":
      break;
  }
  let response: Response;
  try {
    response = await pinnedFetch(url.toString(), {
      method: params.method,
      headers,
      body: outboundBody,
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new HttpError(502, "upstream_unavailable");
  }
  const event = {
    at: new Date().toISOString(),
    alias: params.secret_alias,
    method: params.method,
    host: url.host,
    status: response.status,
  };
  ctx.waitUntil(
    authority(env, principal.tenant, {
      op: "record_audit",
      id: random(12),
      event,
    }).catch(() => undefined),
  );
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    return {
      status: response.status,
      redirectBlocked: true,
      headers: {},
      data: null,
    };
  }
  const type = response.headers.get("content-type") || "";
  const mediaType = type.split(";", 1)[0].trim().toLowerCase();
  const charsetFields = type
    .split(";")
    .slice(1)
    .filter((parameter) => /^\s*charset(?:\s*=|\s*$)/i.test(parameter));
  const charsetMatch =
    charsetFields.length === 1
      ? /^\s*charset\s*=\s*(?:"([^"]+)"|([^";\s]+))\s*$/i.exec(charsetFields[0])
      : null;
  const charset = charsetMatch?.[1] || charsetMatch?.[2];
  const bodyless = !response.body && [204, 205, 304].includes(response.status);
  if (
    (response.headers.has("content-encoding") &&
      !/^identity$/i.test(response.headers.get("content-encoding") || "")) ||
    (!bodyless &&
      !(
        mediaType === "application/json" ||
        /^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(mediaType) ||
        /^text\/[a-z0-9!#$&^_.+-]+$/.test(mediaType) ||
        mediaType === "application/xml" ||
        /^application\/[a-z0-9!#$&^_.+-]+\+xml$/.test(mediaType) ||
        mediaType === "application/x-www-form-urlencoded"
      )) ||
    (charsetFields.length > 0 && (!charset || !/^utf-?8$/i.test(charset)))
  ) {
    await response.body?.cancel();
    throw new HttpError(502, "unsupported_response_type");
  }
  let raw: string;
  try {
    raw = await readText(response, 512 * 1024, true);
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(502, "unsupported_response_encoding");
  }
  let data: unknown = raw;
  let originalJson: string | undefined;
  try {
    data = JSON.parse(raw);
    originalJson = raw;
  } catch {
    /* text response */
  }
  const sanitized = scrubSecretsFromPayload(
    data,
    redactionTargets,
    true,
    originalJson,
  );
  const safeHeaders = sanitizeResponseHeaders(
    response.headers,
    redactionTargets,
  );
  delete safeHeaders.location;
  delete safeHeaders.refresh;
  return {
    status: response.status,
    headers: safeHeaders,
    data: sanitized.sanitized,
    redactionsCount: sanitized.redactionsCount,
  };
}

function substituteBodyPlaceholder(
  body: string,
  secret: string,
  contentType: string,
): string {
  const parameters = contentType.split(";").slice(1);
  const charsetParameters = parameters.filter((parameter) =>
    /^\s*charset(?:\s*=|\s*$)/i.test(parameter),
  );
  if (
    charsetParameters.length > 1 ||
    (charsetParameters.length === 1 &&
      !/^\s*charset\s*=\s*(?:"utf-?8"|utf-?8)\s*$/i.test(charsetParameters[0]))
  )
    throw new HttpError(400, "unsupported_placeholder_charset");
  const jsonType = contentType.split(";", 1)[0].trim().toLowerCase();
  const isJson =
    jsonType === "application/json" ||
    /^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(jsonType);
  if (isJson) {
    let sentinel = "__AGENTSECRET_PLACEHOLDER_SENTINEL__";
    while (body.includes(sentinel)) sentinel += "_";
    const markerIndex = body.indexOf(SECRET_BODY_PLACEHOLDER);
    const inJsonString = isInsideJsonString(body, markerIndex);
    const markerForValidation = inJsonString
      ? sentinel
      : JSON.stringify(sentinel);
    let parsed: unknown;
    try {
      parsed = JSON.parse(
        body.replace(SECRET_BODY_PLACEHOLDER, markerForValidation),
      );
    } catch {
      throw new HttpError(400, "invalid_placeholder_json");
    }
    if (!containsExactStringValue(parsed, sentinel))
      throw new HttpError(400, "invalid_placeholder_json");

    const replacement = inJsonString
      ? JSON.stringify(secret).slice(1, -1)
      : JSON.stringify(secret);
    return body.replace(SECRET_BODY_PLACEHOLDER, () => replacement);
  }
  if (jsonType === "" || jsonType === "text/plain") {
    return body.replace(SECRET_BODY_PLACEHOLDER, () => secret);
  }
  throw new HttpError(400, "unsupported_placeholder_content_type");
}

function isInsideJsonString(text: string, offset: number): boolean {
  let inString = false;
  let escaped = false;
  for (let index = 0; index < offset; index++) {
    const character = text[index];
    if (escaped) {
      escaped = false;
    } else if (character === "\\" && inString) {
      escaped = true;
    } else if (character === '"') {
      inString = !inString;
    }
  }
  return inString && !escaped;
}

function containsExactStringValue(value: unknown, sentinel: string): boolean {
  if (value === sentinel) return true;
  if (Array.isArray(value))
    return value.some((entry) => containsExactStringValue(entry, sentinel));
  if (!value || typeof value !== "object") return false;
  return Object.values(value).some((entry) =>
    containsExactStringValue(entry, sentinel),
  );
}
