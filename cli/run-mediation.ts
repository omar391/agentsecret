/**
 * Host-side mediation for managed runs.
 *
 * The guest receives only short-lived `ASRC1` placeholders. This loopback
 * mediator keeps the agent DPoP session and each one-use broker capability in
 * the host process, validates the guest's placeholder, and forwards one exact
 * request to the cloud broker.
 */

import { createServer, type Server } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { hash, random } from "../src/security/primitives";
import type { Credentials } from "./store";
import type { RunEgressRule, RunSpec } from "./run-spec";
import { signProof } from "../protocol/dpop";

export interface RunBindingToken {
  envName: string;
  alias: string;
  fieldPath?: string;
  token: string;
}

export interface RunMediation {
  origin: string;
  bindings: RunBindingToken[];
  close(): Promise<void>;
}

/** Resolve an alias to its authoritative bound reference (policy secretId). */
export type ResolveAliasReference = (alias: string) => Promise<string>;

function fieldPartOfReference(reference: string): string {
  const index = reference.indexOf("#");
  return index === -1 ? "" : reference.slice(index + 1);
}

/**
 * A declared field must equal the field embedded in the alias's authoritative
 * reference. 1Password Connect references carry a bare field id after '#';
 * their canonical path form is "/fields/<id>". A field-less reference (for
 * example a Bitwarden Secrets Manager object) accepts only the "/" marker.
 */
function declaredFieldMatches(fieldPath: string, reference: string): boolean {
  const fieldId = fieldPartOfReference(reference);
  if (fieldId === "") return fieldPath === "/";
  return fieldPath === fieldId || fieldPath === "/fields/" + fieldId;
}

/** The CLI's restored session plus the in-memory DPoP key pair. */
export type MediationSession = Credentials & { keys: CryptoKeyPair };

export type IssueAndRedeem = (
  request: Record<string, unknown>,
) => Promise<{ status: number; body: string }>;

const MAX_MEDIATION_REQUEST_BYTES = 64 * 1024;
const TOKEN_RANDOM_BYTES = 32;

function tokenFor(alias: string): string {
  return `ASRC1.${alias}.${random(TOKEN_RANDOM_BYTES)}`;
}

function safeEqual(a: string, b: string): boolean {
  const left = createHash("sha256").update(a).digest();
  const right = createHash("sha256").update(b).digest();
  return timingSafeEqual(left, right);
}

/** Brokers return one of these bounded envelopes after a capability redeem. */
export interface MediationReceipt {
  status: number;
  outcome: "known" | "unknown";
  data?: unknown;
}

const MAX_MEDIATION_RESPONSE_BYTES = 512 * 1024;
const SECRET_BODY_PLACEHOLDER = "{{AGENTSECRET_SECRET}}";
const SUPPORTED_METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);
const GIT_REQUEST_CONTENT_TYPES = new Set([
  "application/x-git-upload-pack-request",
  "application/x-git-receive-pack-request",
]);
const GIT_DISCOVERY_SERVICES = new Set([
  "service=git-upload-pack",
  "service=git-receive-pack",
]);

/** Build one opaque placeholder for each declared reference binding. */
export function createRunBindingTokens(spec: RunSpec): RunBindingToken[] {
  const seen = new Set<string>();
  return spec.referenceBindings.map((binding) => {
    const key = binding.envName.toLowerCase();
    if (seen.has(key)) throw new Error("run_binding_env_duplicate");
    seen.add(key);
    return {
      envName: binding.envName,
      alias: binding.alias,
      ...(binding.fieldPath === undefined
        ? {}
        : { fieldPath: binding.fieldPath }),
      token: tokenFor(binding.alias),
    };
  });
}

async function brokerPost(
  route: string,
  value: unknown,
  session: MediationSession,
): Promise<Response> {
  const text = JSON.stringify(value);
  return fetch(session.server + route, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "DPoP " + session.accessToken,
      DPoP: await signProof(
        session.keys,
        "POST",
        session.server + route,
        session.accessToken,
        await hash(text),
      ),
    },
    body: text,
    redirect: "error",
  });
}

function brokerEnvelopeToReceipt(value: unknown): MediationReceipt | undefined {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value as object).some(
      (key) =>
        ![
          "data",
          "headers",
          "outcomeStatus",
          "redirectBlocked",
          "redactionsCount",
          "requestDigest",
          "resultStatus",
          "status",
        ].includes(key),
    ) ||
    !Number.isSafeInteger((value as { status?: unknown }).status) ||
    (value as { status: number }).status < 100 ||
    (value as { status: number }).status > 599
  )
    return undefined;
  const envelope = value as {
    status: number;
    redirectBlocked?: unknown;
    outcomeStatus?: unknown;
    resultStatus?: unknown;
    data?: unknown;
  };
  if (
    envelope.redirectBlocked !== undefined &&
    typeof envelope.redirectBlocked !== "boolean"
  )
    return undefined;
  if (envelope.redirectBlocked === true)
    return { status: envelope.status, outcome: "known" };
  if (envelope.outcomeStatus === 0)
    return { status: envelope.status, outcome: "known", data: envelope.data };
  if (envelope.resultStatus === "unknown")
    return { status: envelope.status, outcome: "unknown" };
  if (envelope.status >= 200 && envelope.status < 400)
    return { status: envelope.status, outcome: "known", data: envelope.data };
  return { status: envelope.status, outcome: "unknown" };
}

/** Issue and redeem one exact-request capability without exposing it to the guest. */
export async function issueAndRedeemProxyCapability(
  request: Record<string, unknown>,
  session: MediationSession,
): Promise<{ status: number; body: string }> {
  const requestBody = JSON.stringify(request);
  if (Buffer.byteLength(requestBody, "utf8") > 60 * 1024)
    throw new Error("gateway_broker_request_too_large");
  const issued = await brokerPost(
    "/api/agent/proxy-capabilities",
    request,
    session,
  );
  if (!issued.ok) throw new Error("proxy_capability_issue_failed");
  const issueText = await issued.text();
  if (Buffer.byteLength(issueText, "utf8") > 4096)
    throw new Error("proxy_capability_issue_failed");
  let envelope: unknown;
  try {
    envelope = JSON.parse(issueText);
  } catch {
    throw new Error("proxy_capability_issue_failed");
  }
  if (
    !envelope ||
    typeof envelope !== "object" ||
    Array.isArray(envelope) ||
    Object.keys(envelope as object)
      .sort()
      .join(",") !== "capability,expiresAt" ||
    typeof (envelope as { capability?: unknown }).capability !== "string" ||
    !Number.isSafeInteger((envelope as { expiresAt?: unknown }).expiresAt)
  )
    throw new Error("proxy_capability_issue_failed");
  const capability = (envelope as { capability: string }).capability;
  const parts = capability.split(".");
  if (
    parts.length !== 3 ||
    parts[0] !== "aspc1" ||
    parts[1] !== session.tenant ||
    !/^[A-Za-z0-9_-]{43}$/.test(parts[2])
  )
    throw new Error("proxy_capability_issue_failed");
  const redeemed = await fetch(session.server + "/proxy/capability", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "AgentSecret " + capability,
    },
    body: requestBody,
    redirect: "error",
  });
  return { status: redeemed.status, body: await redeemed.text() };
}

interface ValidProxyRequest {
  secret_alias: string;
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  response_mode?: "git";
}

function isReservedHeaderName(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    /^(authorization|proxy-authorization|cookie|host|connection|content-length|transfer-encoding|forwarded|x-forwarded-host|x-forwarded-for|x-forwarded-proto|x-forwarded-port|x-api-key|api-key|accept-encoding|content-encoding)$/u.test(
      name,
    ) ||
    lower.startsWith("cf-") ||
    lower.startsWith("sec-")
  );
}

function isUnsupportedTransportHeader(name: string): boolean {
  return /^(keep-alive|proxy-connection|proxy-authenticate|te|trailer|upgrade|expect)$/iu.test(
    name,
  );
}

function isSafeHttpsUrl(value: string): boolean {
  const rest = /^https:\/\/(.*)$/u.exec(value)?.[1];
  if (
    rest === undefined ||
    rest.length > 4096 ||
    rest.includes("@") ||
    rest.includes("#")
  )
    return false;
  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const pathAndQuery = slash === -1 ? "" : rest.slice(slash + 1);
  if (authority.includes(":")) return false;
  const path = pathAndQuery.split("?")[0] ?? "";
  if (path === "") return true;
  const lower = path.toLowerCase();
  return (
    !/[\u0000-\u001f\u007f]/u.test(path) &&
    !path.includes("//") &&
    !path.split("/").some((part) => part === "." || part === "..") &&
    !lower.includes("%2f") &&
    !lower.includes("%5c") &&
    !lower.includes("%2e") &&
    !lower.includes("%25")
  );
}

function isValidHeaderName(name: string): boolean {
  return (
    name.length > 0 &&
    name.length <= 80 &&
    /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name)
  );
}

function isValidHeaderValue(value: string): boolean {
  return (
    value === value.trim() &&
    value.length <= 4096 &&
    /^[\u0020-\u007e]*$/u.test(value)
  );
}

/**
 * Validate the exact broker request shape before any capability is issued.
 *
 * The rules mirror the Rust gateway and cloud broker: HTTPS only, supported
 * methods, no reserved transport headers, and exactly one secret placeholder
 * in a JSON or plain-text body.
 */
export function validProxyRequestShape(
  value: unknown,
): value is ValidProxyRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (
    !["secret_alias", "url", "method"].every((key) => key in record) ||
    keys.some(
      (key) =>
        ![
          "body",
          "headers",
          "method",
          "response_mode",
          "secret_alias",
          "url",
        ].includes(key),
    )
  )
    return false;
  if (
    typeof record.secret_alias !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,63}$/u.test(record.secret_alias) ||
    typeof record.url !== "string" ||
    !isSafeHttpsUrl(record.url) ||
    typeof record.method !== "string" ||
    !SUPPORTED_METHODS.has(record.method) ||
    (record.response_mode !== undefined && record.response_mode !== "git")
  )
    return false;
  if (record.headers !== undefined) {
    if (
      typeof record.headers !== "object" ||
      Array.isArray(record.headers) ||
      Object.keys(record.headers as object).length > 32
    )
      return false;
    for (const [name, headerValue] of Object.entries(
      record.headers as Record<string, unknown>,
    )) {
      if (
        typeof headerValue !== "string" ||
        isReservedHeaderName(name) ||
        isUnsupportedTransportHeader(name) ||
        !isValidHeaderName(name) ||
        !isValidHeaderValue(headerValue)
      )
        return false;
    }
  }
  if (record.body === undefined) {
    return record.method === "GET" || record.method === "HEAD";
  }
  const contentType = Object.entries(
    (record.headers ?? {}) as Record<string, string>,
  )
    .find(([name]) => name.toLowerCase() === "content-type")
    ?.at(1)
    ?.split(";")[0]
    ?.trim()
    ?.toLowerCase();
  if (record.response_mode === "git") {
    return (
      typeof record.body === "string" &&
      GIT_REQUEST_CONTENT_TYPES.has(contentType ?? "") &&
      !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(record.body)
    );
  }
  if (typeof record.body !== "string") return false;
  const placeholders = record.body.split(SECRET_BODY_PLACEHOLDER).length - 1;
  return (
    (contentType === "application/json" || contentType === "text/plain") &&
    placeholders === 1 &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(record.body)
  );
}

/**
 * Start the host-only mediation endpoint. The caller supplies the already
 * authenticated agent session; no credential or capability is returned to the
 * guest.
 */
export async function startRunMediator(options: {
  session: MediationSession;
  bindings: RunBindingToken[];
  egress: RunEgressRule[];
  issueAndRedeem?: IssueAndRedeem;
  resolveAliasReference?: ResolveAliasReference;
  signal?: AbortSignal;
  host?: string;
}): Promise<RunMediation> {
  const bindings = options.bindings;
  if (!bindings.length) throw new Error("run_reference_bindings_required");
  const egress = options.egress;
  if (!Array.isArray(egress)) throw new Error("run_mediation_egress_required");
  const fieldBindings = bindings.filter(
    (binding) => binding.fieldPath !== undefined,
  );
  if (fieldBindings.length && options.resolveAliasReference === undefined)
    throw new Error("run_binding_field_unverified");
  const references = new Map<string, Promise<string>>();
  for (const binding of fieldBindings) {
    if (!references.has(binding.alias))
      references.set(
        binding.alias,
        options.resolveAliasReference!(binding.alias),
      );
    const reference = await references.get(binding.alias)!;
    if (!declaredFieldMatches(binding.fieldPath!, reference))
      throw new Error("run_binding_field_mismatch");
  }
  const dispatch =
    options.issueAndRedeem ??
    ((request) => issueAndRedeemProxyCapability(request, options.session));
  if (options.session.expiresAt <= Date.now() + 60_000)
    throw new Error("session_expired");
  const forbidden = [
    options.session.accessToken,
    ...bindings.map((binding) => binding.token),
  ];
  const server: Server = createServer(async (request, response) => {
    const fail = (status: number, code: string) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: code }));
    };
    if (request.method !== "POST" || request.url !== "/mediate") {
      fail(404, "mediation_route_not_found");
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      for await (const chunk of request) {
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += bytes.byteLength;
        if (size > MAX_MEDIATION_REQUEST_BYTES) {
          request.destroy();
          return;
        }
        chunks.push(bytes);
      }
    } catch {
      return;
    }
    let input: unknown;
    try {
      input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      fail(400, "mediation_request_invalid_json");
      return;
    }
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input as object)
        .sort()
        .join(",") !== "request,run_token" ||
      typeof (input as { run_token?: unknown }).run_token !== "string"
    ) {
      fail(400, "mediation_request_invalid");
      return;
    }
    const { run_token: runToken, request: proxyRequest } = input as {
      run_token: string;
      request: unknown;
    };
    const binding = bindings.find((candidate) =>
      safeEqual(candidate.token, runToken),
    );
    if (
      !binding ||
      !validProxyRequestShape(proxyRequest) ||
      proxyRequest.secret_alias !== binding.alias
    ) {
      fail(403, "mediation_token_invalid");
      return;
    }
    let requestUrl: URL;
    try {
      requestUrl = new URL(proxyRequest.url);
    } catch {
      fail(403, "mediation_egress_denied");
      return;
    }
    const granted = egress.some(
      (rule) =>
        rule.host === requestUrl.hostname &&
        rule.method === proxyRequest.method &&
        rule.path === requestUrl.pathname &&
        (requestUrl.search === "" ||
          (proxyRequest.response_mode === "git" &&
            GIT_DISCOVERY_SERVICES.has(requestUrl.search.slice(1)))),
    );
    if (!granted) {
      fail(403, "mediation_egress_denied");
      return;
    }
    try {
      const result = await dispatch(
        proxyRequest as unknown as Record<string, unknown>,
      );
      if (
        Buffer.byteLength(result.body, "utf8") > MAX_MEDIATION_RESPONSE_BYTES
      ) {
        fail(502, "gateway_broker_response_too_large");
        return;
      }
      // A broker failure is not an authorization to perform local delivery.
      // No local delivery contract exists yet, so never synthesize success.
      if (result.status < 200 || result.status >= 300) {
        fail(502, "gateway_broker_unavailable");
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(result.body);
      } catch {
        fail(502, "gateway_broker_invalid_response");
        return;
      }
      const receipt = brokerEnvelopeToReceipt(parsed);
      if (!receipt) {
        fail(502, "gateway_broker_invalid_response");
        return;
      }
      const output = JSON.stringify({
        status: receipt.status,
        outcome: receipt.outcome,
        ...(receipt.data === undefined ? {} : { data: receipt.data }),
      });
      if (
        forbidden.some((secret) => secret.length > 0 && output.includes(secret))
      ) {
        fail(502, "gateway_response_refused");
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(output);
    } catch (error) {
      const code =
        error instanceof Error && /^[a-z0-9_]{1,80}$/.test(error.message)
          ? error.message
          : "gateway_execution_failed";
      fail(502, code);
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, options.host ?? "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address !== "object")
    throw new Error("mediation_listen_failed");
  const close = async () => {
    if (!server.listening) return;
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  };
  const abort = () => {
    void close().catch(() => undefined);
  };
  options.signal?.addEventListener("abort", abort, { once: true });
  server.once("close", () =>
    options.signal?.removeEventListener("abort", abort),
  );
  return {
    origin: `http://${address.address === "::1" ? "[::1]" : address.address}:${address.port}`,
    bindings,
    close,
  };
}
