#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { execFile, execFileSync, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { StringDecoder } from "node:string_decoder";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import path, { join } from "node:path";
import { exportJWK } from "jose";
import { signProof } from "../protocol/dpop";
import {
  hash,
  hasUnsafeConnectReferenceCharacter,
  hasUnsafeConnectReferenceText,
  isWellFormedUnicode,
  parseConnectReference,
  random,
} from "../src/security/primitives";
import { SECRET_BODY_PLACEHOLDER } from "../src/constants";
import {
  normalizeNamedSecretLocatorBinding,
  normalizeNamedSecretLocatorInputBinding,
  normalizeLoginLookupLocatorBinding,
  normalizeLoginLookupLocatorInputBinding,
  normalizeSecretRefBinding,
  normalizeSecretRefInputBinding,
  normalizeEnvVarLocatorBinding,
  normalizeEnvVarLocatorInputBinding,
  COMPANION_ONLY_STORES,
  LOCATOR_UNSUPPORTED_STORES,
} from "../protocol/consumer-bindings";
import {
  load,
  save,
  privateKey,
  clear,
  clearIfUnchanged,
  beginPendingSecretWrite,
  completePendingSecretWrite,
  type Credentials,
  configDir,
} from "./store";
import {
  createSigningPair,
  restoreSigningPair,
  signingPairForLogin,
} from "./keys";
import {
  macOsKeychainProviderCredentials,
  type ProviderCredentialBinding,
} from "./provider-credentials";
import {
  BitwardenPasswordManagerAdapter,
  inspectFastflowBitwardenProfile,
  serializeFastflowBitwardenProfile,
} from "./providers/bitwarden-password-manager";
import {
  OnePasswordServiceAccountAdapter,
  parseOnePasswordServiceAccountReference,
  serializeOnePasswordServiceAccountProfile,
} from "./providers/onepassword-service-account";
import {
  LastPassAdapter,
  serializeLastPassProfile,
} from "./providers/lastpass";
import {
  createExecutorIdentity,
  executorProof,
  publicExecutorIdentity,
} from "./browser/executor";
import {
  launchChromeDriver,
  TRUSTED_CHROME_EXECUTABLE,
  verifyTrustedChromeInstallation,
} from "./browser/chrome";
import { BrowserActionReceiptStore } from "./browser/receipt-store";
import {
  BrowserActionError,
  BrowserActionSetupError,
  guardServiceAccountClient,
  runBrowserAction,
} from "./browser/action";
import { ExecutorStore, macOsExecutorBackend } from "./browser/executor-store";
import { parseRunArgs, RunSpecError, type RunSpec } from "./run-spec";
import {
  managedBrowserReceiptDirectory,
  parseManagedBrowserArgs,
  runManagedBrowserAction,
} from "./run-browser";
import {
  runGuestCommand,
  runtimeQualified,
  SBX_QUALIFIED_VERSION,
  SBX_QUALIFIED_SHA256,
  T015_EVIDENCE_SHA256,
  writeRuntimeQualificationReceipt,
} from "./docker-runtime";
import { realpathSync } from "node:fs";
const args = process.argv.slice(2);
const command = args.shift() || "help";
const operation = new AbortController();
let signalExitCode: number | undefined;
let proxyCapabilityRedemptionStarted = false;
process.once("SIGINT", () => {
  signalExitCode = 130;
  operation.abort(new Error("Operation cancelled by SIGINT."));
});
process.once("SIGTERM", () => {
  signalExitCode = 143;
  operation.abort(new Error("Operation cancelled by SIGTERM."));
});
function requestSignal(timeoutMs: number) {
  return AbortSignal.any([operation.signal, AbortSignal.timeout(timeoutMs)]);
}
function hasDuplicateJsonKeys(input: string): boolean {
  let cursor = 0;
  const whitespace = () => {
    while (/\s/.test(input[cursor] || "")) cursor++;
  };
  const stringEnd = () => {
    const start = cursor++;
    while (cursor < input.length) {
      if (input[cursor] === "\\") cursor += 2;
      else if (input[cursor++] === '"') return cursor;
    }
    return start;
  };
  const value = (): boolean => {
    whitespace();
    if (input[cursor] === '"') {
      stringEnd();
      return false;
    }
    if (input[cursor] === "{") {
      cursor++;
      whitespace();
      const keys = new Set<string>();
      if (input[cursor] === "}") {
        cursor++;
        return false;
      }
      while (cursor < input.length) {
        whitespace();
        const start = cursor;
        const end = stringEnd();
        const key = JSON.parse(input.slice(start, end)) as string;
        if (keys.has(key)) return true;
        keys.add(key);
        whitespace();
        cursor++; // colon
        if (value()) return true;
        whitespace();
        if (input[cursor] === "}") {
          cursor++;
          return false;
        }
        cursor++; // comma
      }
      return false;
    }
    if (input[cursor] === "[") {
      cursor++;
      whitespace();
      if (input[cursor] === "]") {
        cursor++;
        return false;
      }
      while (cursor < input.length) {
        if (value()) return true;
        whitespace();
        if (input[cursor] === "]") {
          cursor++;
          return false;
        }
        cursor++; // comma
      }
      return false;
    }
    while (cursor < input.length && !/[\s,}\]]/.test(input[cursor])) cursor++;
    return false;
  };
  return value();
}
async function readRequestStdin(maxBytes = 48 * 1024): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  const abortInput = () =>
    process.stdin.destroy(
      operation.signal.reason instanceof Error
        ? operation.signal.reason
        : new Error("Operation cancelled."),
    );
  operation.signal.addEventListener("abort", abortInput, { once: true });
  try {
    for await (const chunk of process.stdin) {
      operation.signal.throwIfAborted();
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > maxBytes) throw new Error("Request input exceeds size limit.");
      chunks.push(bytes);
    }
    operation.signal.throwIfAborted();
  } finally {
    operation.signal.removeEventListener("abort", abortInput);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.concat(chunks),
    );
  } catch {
    throw new Error("Request input must be valid UTF-8 JSON.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Request input must be valid JSON.");
  }
  if (hasDuplicateJsonKeys(text))
    throw new Error("Request input must not contain duplicate JSON keys.");
  return parsed;
}
function validateRequestHeaders(value: unknown): Record<string, string> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length > 32
  )
    throw new Error("Request headers must be a bounded JSON object.");
  const headers = value as Record<string, unknown>;
  const names = new Set<string>();
  for (const [name, headerValue] of Object.entries(headers)) {
    const lowerName = name.toLowerCase();
    if (
      names.has(lowerName) ||
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(name) ||
      typeof headerValue !== "string" ||
      Buffer.byteLength(headerValue, "utf8") > 4096 ||
      headerValue !== headerValue.trim() ||
      /[\u0000-\u0008\u000a-\u001f\u007f]/.test(headerValue) ||
      [...headerValue].some((character) => character.codePointAt(0)! > 0x7e) ||
      /^(authorization|proxy-authorization|cookie|host|connection|content-length|transfer-encoding|forwarded|x-forwarded-.*|cf-.*|sec-.*|x-api-key|api-key|accept-encoding)$/i.test(
        name,
      ) ||
      /^(keep-alive|proxy-connection|proxy-authenticate|te|trailer|upgrade|expect)$/i.test(
        name,
      ) ||
      (/^content-encoding$/i.test(name) && !/^identity$/i.test(headerValue))
    )
      throw new Error("Request contains an unsupported header.");
    names.add(lowerName);
  }
  return headers as Record<string, string>;
}
function waitForOperation(ms: number) {
  operation.signal.throwIfAborted();
  return new Promise<void>((resolve, reject) => {
    const finish = () => {
      operation.signal.removeEventListener("abort", cancel);
      resolve();
    };
    const timer = setTimeout(finish, ms);
    const cancel = () => {
      clearTimeout(timer);
      operation.signal.removeEventListener("abort", cancel);
      reject(operation.signal.reason || new Error("Operation cancelled."));
    };
    operation.signal.addEventListener("abort", cancel, { once: true });
  });
}
function option(name: string) {
  const at = args.indexOf("--" + name);
  return at < 0 ? undefined : args[at + 1];
}
function serverOrigin(value: string) {
  const u = new URL(value);
  if (
    (u.protocol !== "https:" &&
      !(
        u.protocol === "http:" &&
        ["127.0.0.1", "localhost"].includes(u.hostname)
      )) ||
    u.username ||
    u.password ||
    u.search ||
    u.hash ||
    u.pathname !== "/"
  )
    throw new Error(
      "Use the broker HTTPS origin, or an explicit localhost development origin.",
    );
  return u.origin;
}
function validLocalSession(value: ReturnType<typeof load>): boolean {
  return !!(
    value &&
    typeof value.server === "string" &&
    !!value.server &&
    typeof value.accessToken === "string" &&
    !!value.accessToken &&
    typeof value.tenant === "string" &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > 0
  );
}
async function post(
  server: string,
  route: string,
  value: unknown,
  keys?: CryptoKeyPair,
) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (keys) headers.DPoP = await signProof(keys, "POST", server + route);
  const res = await fetch(server + route, {
    method: "POST",
    headers,
    body: JSON.stringify(value),
    redirect: "error",
    signal: requestSignal(15000),
  });
  operation.signal.throwIfAborted();
  const data = (await res.json()) as any;
  return { res, data };
}
async function login(server: string, device: boolean, writeAccess = false) {
  const existing = load();
  const reusedKey =
    existing?.server === server ? privateKey(server) : undefined;
  const keys = await signingPairForLogin(
    server,
    existing?.server,
    () => reusedKey!,
  );
  let data: any;
  if (device) {
    const start = await post(
      server,
      "/oauth/device/code",
      {
        client_id: "agentsecret-cli",
        tenant: option("tenant") || "default",
        aliases: (option("aliases") || option("alias") || "")
          .split(",")
          .filter(Boolean)
          .map((alias) => alias.trim().toUpperCase()),
        scope: writeAccess
          ? ["secrets:proxy", "secrets:read", "secrets:write"]
          : ["secrets:proxy", "secrets:read"],
      },
      keys,
    );
    if (!start.res.ok)
      throw new Error(
        "Device authorization could not start: " + start.data.error,
      );
    console.error(
      "Open " +
        start.data.verification_uri_complete +
        "\nConfirm code: " +
        start.data.user_code,
    );
    const deadline = Date.now() + start.data.expires_in * 1000;
    let interval = start.data.interval || 5;
    while (Date.now() < deadline) {
      await waitForOperation(interval * 1000);
      const result = await post(
        server,
        "/oauth/token",
        {
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          client_id: "agentsecret-cli",
          device_code: start.data.device_code,
        },
        keys,
      );
      if (result.res.ok) {
        data = result.data;
        break;
      }
      if (result.data.error === "slow_down") {
        interval += 5;
        continue;
      }
      if (result.data.error !== "authorization_pending")
        throw new Error("Device authorization failed: " + result.data.error);
    }
    if (!data) throw new Error("Device authorization expired.");
  } else {
    const verifier = random();
    const state = random();
    data = await new Promise<any>((resolve, reject) => {
      let exchanging = false;
      let timeout: ReturnType<typeof setTimeout>;
      const listener = createServer(async (req, res) => {
        const callback = new URL(req.url || "/", "http://127.0.0.1");
        if (
          req.method !== "GET" ||
          callback.pathname !== "/callback" ||
          callback.searchParams.get("state") !== state ||
          !callback.searchParams.get("code")
        ) {
          res.writeHead(400);
          res.end("Invalid authorization response.");
          return;
        }
        if (exchanging) {
          res.writeHead(409);
          res.end("Authorization already in progress.");
          return;
        }
        exchanging = true;
        try {
          const address = listener.address() as { port: number };
          const result = await post(
            server,
            "/oauth/token",
            {
              grant_type: "authorization_code",
              client_id: "agentsecret-cli",
              redirect_uri: `http://127.0.0.1:${address.port}/callback`,
              code: callback.searchParams.get("code"),
              code_verifier: verifier,
            },
            keys,
          );
          if (!result.res.ok)
            throw new Error(
              "Authorization exchange failed: " + result.data.error,
            );
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("AgentSecret authorized. You may close this window.");
          cleanup();
          resolve(result.data);
        } catch (error) {
          res.writeHead(400);
          res.end("Authorization failed.");
          cleanup();
          reject(error);
        }
      });
      const cleanup = () => {
        operation.signal.removeEventListener("abort", cancel);
        listener.close();
        clearTimeout(timeout);
      };
      const cancel = () => {
        listener.closeAllConnections();
        cleanup();
        reject(operation.signal.reason || new Error("Operation cancelled."));
      };
      operation.signal.addEventListener("abort", cancel, { once: true });
      timeout = setTimeout(() => {
        listener.closeAllConnections();
        cleanup();
        reject(new Error("Authorization timed out."));
      }, 180000);
      listener.once("error", (error) => {
        cleanup();
        reject(error);
      });
      listener.listen(0, "127.0.0.1", async () => {
        const address = listener.address() as { port: number };
        const url = new URL(server + "/oauth/authorize");
        url.search = new URLSearchParams({
          response_type: "code",
          client_id: "agentsecret-cli",
          redirect_uri: `http://127.0.0.1:${address.port}/callback`,
          code_challenge: await hash(verifier),
          code_challenge_method: "S256",
          state,
          aliases: option("aliases") || option("alias") || "",
          scope: writeAccess
            ? "secrets:proxy secrets:read secrets:write"
            : "secrets:proxy secrets:read",
        }).toString();
        console.error("Authorize this login in your browser:\n" + url);
        const executable =
          process.platform === "darwin"
            ? "open"
            : process.platform === "win32"
              ? null
              : "xdg-open";
        if (executable)
          execFile(
            executable,
            [url.toString()],
            { signal: operation.signal },
            () => undefined,
          );
      });
    });
  }
  const tenant = new TextDecoder().decode(
    Uint8Array.from(Buffer.from(data.access_token.split(".")[1], "base64url")),
  );
  save(
    {
      server,
      tenant,
      accessToken: data.access_token,
      expiresAt: Date.now() + data.expires_in * 1000,
    },
    reusedKey ?? (await exportJWK(keys.privateKey)),
  );
  console.error(
    "Authenticated. Signing key stored by the operating system; session metadata is private to this user.",
  );
}
async function ci(server: string) {
  let assertion = process.env.AGENTSECRET_OIDC_TOKEN;
  if (
    !assertion &&
    process.env.ACTIONS_ID_TOKEN_REQUEST_URL &&
    process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  ) {
    const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
    if (
      url.protocol !== "https:" ||
      !url.hostname.endsWith(".actions.githubusercontent.com")
    )
      throw new Error("Untrusted workload assertion endpoint.");
    url.searchParams.set("audience", server);
    const response = await fetch(url, {
      headers: {
        Authorization: "Bearer " + process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
      },
      redirect: "error",
      signal: requestSignal(15000),
    });
    if (!response.ok) throw new Error("Workload assertion unavailable.");
    assertion = ((await response.json()) as any).value;
    operation.signal.throwIfAborted();
  }
  if (!assertion) throw new Error("No CI identity assertion is configured.");
  const keys = await createSigningPair();
  const result = await post(
    server,
    "/oauth/token/oidc",
    { oidc_token: assertion },
    keys,
  );
  if (!result.res.ok)
    throw new Error("Workload exchange denied: " + result.data.error);
  const tokenParts = String(result.data.access_token).split(".");
  let tenant = "federated";
  if (tokenParts[0] === "as2" && tokenParts[1]) {
    try {
      tenant = Buffer.from(tokenParts[1], "base64url").toString("utf8");
    } catch {
      throw new Error("Workload exchange returned an invalid session token.");
    }
  }
  return {
    server,
    tenant,
    accessToken: result.data.access_token,
    expiresAt: Date.now() + result.data.expires_in * 1000,
    keys,
  };
}
let cached:
  | {
      server: string;
      tenant: string;
      accessToken: string;
      expiresAt: number;
      keys: CryptoKeyPair;
    }
  | undefined;
async function credentials() {
  if (cached && cached.expiresAt > Date.now() + 30000) return cached;
  const stored = load();
  if (stored && !validLocalSession(stored))
    throw new Error(
      "Local session metadata is invalid; clear it and log in again.",
    );
  const server = serverOrigin(
    option("server") || process.env.AGENTSECRET_SERVER || stored?.server || "",
  );
  if (
    process.env.AGENTSECRET_OIDC_TOKEN ||
    process.env.ACTIONS_ID_TOKEN_REQUEST_URL
  )
    return (cached = await ci(server));
  if (!stored || stored.server !== server || stored.expiresAt <= Date.now()) {
    if (!process.stdin.isTTY)
      throw new Error(
        "Authenticate first with agentsecret login --server <origin> --device, or configure CI federation.",
      );
    await login(server, args.includes("--device"), args.includes("--write"));
    return credentials();
  }
  const keys = await restoreSigningPair(privateKey(server));
  return (cached = { ...stored, keys });
}
async function remoteAgentStatus(
  session: Awaited<ReturnType<typeof credentials>>,
): Promise<"authenticated" | "rejected" | "unavailable"> {
  try {
    const response = await fetch(session.server + "/api/agent/status", {
      method: "GET",
      headers: {
        Authorization: "DPoP " + session.accessToken,
        DPoP: await signProof(
          session.keys,
          "GET",
          session.server + "/api/agent/status",
          session.accessToken,
        ),
      },
      redirect: "error",
      signal: requestSignal(10000),
    });
    operation.signal.throwIfAborted();
    if (response.status === 401 || response.status === 403) return "rejected";
    if (!response.ok) return "unavailable";
    const result: unknown = await response.json();
    if (
      !result ||
      typeof result !== "object" ||
      Array.isArray(result) ||
      Object.keys(result).sort().join(",") !== "expiresAt,status" ||
      (result as { status?: unknown }).status !== "authenticated" ||
      !Number.isSafeInteger((result as { expiresAt?: unknown }).expiresAt) ||
      (result as { expiresAt: number }).expiresAt <=
        Math.floor(Date.now() / 1000) ||
      (result as { expiresAt: number }).expiresAt >
        Math.ceil(session.expiresAt / 1000) + 1
    )
      return "unavailable";
    return "authenticated";
  } catch {
    operation.signal.throwIfAborted();
    return "unavailable";
  }
}
async function remoteAliasStatus(
  session: Awaited<ReturnType<typeof credentials>>,
  alias: string,
): Promise<"ready" | "requires_companion" | "not_found" | "unavailable"> {
  try {
    const response = await broker(
      "/mcp",
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "list_available_secrets", arguments: {} },
      },
      session,
    );
    if (!response.ok) return "unavailable";
    const envelope: unknown = await response.json();
    if (
      !envelope ||
      typeof envelope !== "object" ||
      Array.isArray(envelope) ||
      (envelope as { jsonrpc?: unknown }).jsonrpc !== "2.0" ||
      (envelope as { id?: unknown }).id !== 1 ||
      (envelope as { error?: unknown }).error !== undefined
    )
      return "unavailable";
    const result = (envelope as { result?: unknown }).result;
    if (!result || typeof result !== "object" || Array.isArray(result))
      return "unavailable";
    const resultObject = result as {
      isError?: unknown;
      content?: unknown;
    };
    if (
      resultObject.isError === true ||
      !Array.isArray(resultObject.content) ||
      !resultObject.content[0] ||
      typeof resultObject.content[0] !== "object" ||
      resultObject.content[0].type !== "text" ||
      typeof resultObject.content[0].text !== "string"
    )
      return "unavailable";
    const payload: unknown = JSON.parse(resultObject.content[0].text);
    if (!payload || typeof payload !== "object" || Array.isArray(payload))
      return "unavailable";
    const aliases = (payload as { available_secrets?: unknown })
      .available_secrets;
    if (!Array.isArray(aliases)) return "unavailable";
    const matching = aliases.filter(
      (entry) =>
        !!entry &&
        typeof entry === "object" &&
        !Array.isArray(entry) &&
        (entry as { alias?: unknown }).alias === alias,
    );
    if (!matching.length) return "not_found";
    if (matching.length !== 1) return "unavailable";
    const entry = matching[0] as {
      connection_status?: unknown;
      provider_mode?: unknown;
      provider_capabilities?: unknown;
      companion_binding?: unknown;
    };
    const capabilities = entry.provider_capabilities;
    if (
      entry.connection_status !== "ready" ||
      !capabilities ||
      typeof capabilities !== "object" ||
      Array.isArray(capabilities)
    )
      return "unavailable";
    const providerStatus = (capabilities as { status?: unknown }).status;
    if (
      [
        "bitwarden-password-manager",
        "onepassword-service-account",
        "lastpass",
      ].includes(entry.provider_mode as string)
    ) {
      const binding = entry.companion_binding;
      if (
        providerStatus !== "requires-companion" ||
        !binding ||
        typeof binding !== "object" ||
        Array.isArray(binding) ||
        typeof (binding as { connection_id?: unknown }).connection_id !==
          "string" ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(
          (binding as { connection_id: string }).connection_id,
        ) ||
        !Number.isSafeInteger(
          (binding as { connection_revision?: unknown }).connection_revision,
        ) ||
        (binding as { connection_revision: number }).connection_revision < 1
      )
        return "unavailable";
      return "requires_companion";
    }
    if (
      !["bitwarden-secrets-manager", "onepassword-connect"].includes(
        entry.provider_mode as string,
      ) ||
      providerStatus !== "implemented" ||
      (capabilities as { read?: unknown }).read !== true
    )
      return "unavailable";
    return "ready";
  } catch {
    operation.signal.throwIfAborted();
    return "unavailable";
  }
}
async function broker(
  route: string,
  value: unknown,
  authenticatedSession?: Awaited<ReturnType<typeof credentials>>,
) {
  const session = authenticatedSession || (await credentials());
  const text = JSON.stringify(value);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-06-18",
    Authorization: "DPoP " + session.accessToken,
    DPoP: await signProof(
      session.keys,
      "POST",
      session.server + route,
      session.accessToken,
      await hash(text),
    ),
  };
  return fetch(session.server + route, {
    method: "POST",
    headers,
    body: text,
    redirect: "error",
    signal: requestSignal(20000),
  });
}

async function localCompanionBroker(
  route: string,
  body: Record<string, unknown>,
  session: Awaited<ReturnType<typeof credentials>>,
  executor: Awaited<ReturnType<ExecutorStore["load"]>>,
) {
  if (!executor) throw new Error("trusted_executor_not_enrolled");
  const text = JSON.stringify(body);
  const requestHash = await hash(text);
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
        requestHash,
      ),
      "X-AgentSecret-Executor-Proof": await executorProof(
        executor,
        "POST",
        session.server + route,
        undefined,
        requestHash,
      ),
    },
    body: text,
    redirect: "error",
    signal: requestSignal(20000),
  });
}

async function serviceAccountBindingForAlias(
  session: Awaited<ReturnType<typeof credentials>>,
  alias: string,
  intent: "create" | "update" | "delete",
): Promise<ProviderCredentialBinding | null> {
  const path =
    "/api/agent/secrets/provider?alias=" +
    encodeURIComponent(alias) +
    "&intent=" +
    intent;
  const url = session.server + path;
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: "DPoP " + session.accessToken,
      DPoP: await signProof(session.keys, "GET", url, session.accessToken),
    },
    redirect: "error",
    signal: requestSignal(10000),
  });
  if (!response.ok)
    throw new Error("Broker could not determine the vault provider.");
  const value: unknown = await response.json();
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Broker returned an invalid provider result.");
  const record = value as Record<string, unknown>;
  if (
    typeof record.provider !== "string" ||
    typeof record.connectionId !== "string" ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(record.connectionId) ||
    !Number.isSafeInteger(record.revision) ||
    (record.revision as number) < 1
  )
    throw new Error("Broker returned an invalid provider result.");
  if (
    ![
      "bitwarden",
      "bitwarden-password-manager",
      "lastpass",
      "onepassword-connect",
      "onepassword-service-account",
    ].includes(record.provider)
  )
    throw new Error("Broker returned an invalid provider result.");
  if (
    ![
      "bitwarden-password-manager",
      "lastpass",
      "onepassword-service-account",
    ].includes(record.provider)
  )
    return null;
  return {
    server: session.server,
    tenant: session.tenant,
    connectionId: record.connectionId,
    connectionRevision: record.revision as number,
    providerMode: record.provider as
      "bitwarden-password-manager" | "lastpass" | "onepassword-service-account",
  };
}

async function mcpToolResult(
  session: Awaited<ReturnType<typeof credentials>>,
  name: string,
  arguments_: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await broker(
    "/mcp",
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: arguments_ },
    },
    session,
  );
  if (!response.ok)
    throw new Error("Broker denied the local companion request.");
  const envelope: any = await response.json();
  if (
    !envelope ||
    envelope.jsonrpc !== "2.0" ||
    envelope.id !== 1 ||
    Object.hasOwn(envelope, "error") ||
    envelope.result?.isError === true ||
    !Array.isArray(envelope.result?.content) ||
    envelope.result.content.length !== 1 ||
    envelope.result.content[0]?.type !== "text" ||
    typeof envelope.result.content[0].text !== "string"
  )
    throw new Error("Broker returned an invalid local companion result.");
  const result: unknown = JSON.parse(envelope.result.content[0].text);
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new Error("Broker returned an invalid local companion result.");
  return result as Record<string, unknown>;
}

function serviceAccountWriteReceipt(
  intent: "create" | "update" | "ensure",
  result: Record<string, unknown>,
  expectedReference?: string,
): {
  status: "created" | "updated" | "unchanged";
  reference: string;
  verified: true;
} {
  const status =
    result.status === "saved"
      ? intent === "ensure"
        ? String(result.resultStatus)
        : intent === "create"
          ? "created"
          : "updated"
      : String(result.status);
  const expectedStatus =
    intent === "create"
      ? ["created"]
      : intent === "update"
        ? ["updated"]
        : ["unchanged", "updated"];
  if (
    !expectedStatus.includes(status) ||
    typeof result.reference !== "string" ||
    !result.reference ||
    (expectedReference !== undefined &&
      result.reference !== expectedReference) ||
    result.verified !== true ||
    (result.replayed !== undefined && typeof result.replayed !== "boolean")
  )
    throw new Error("Broker returned an invalid local companion receipt.");
  return {
    status: status as "created" | "updated" | "unchanged",
    reference: result.reference,
    verified: true,
  };
}

function serviceAccountDeleteReceipt(
  receipt: unknown,
  reference: string,
): { status: "deleted"; reference: string; verified: true } {
  if (
    !receipt ||
    typeof receipt !== "object" ||
    Array.isArray(receipt) ||
    (receipt as Record<string, unknown>).status !== "saved" ||
    (receipt as Record<string, unknown>).reference !== reference ||
    (receipt as Record<string, unknown>).verified !== true
  )
    throw new Error("The local companion deletion receipt is invalid.");
  return { status: "deleted", reference, verified: true };
}

async function fulfillServiceAccountWrite(
  session: Awaited<ReturnType<typeof credentials>>,
  binding: ProviderCredentialBinding,
  alias: string,
  action: "save" | "update" | "ensure",
  target: string,
  operationId: string,
  value: string,
  existingRequestId?: string,
  authorizeDispatch?: () => void,
): Promise<
  | { status: "created" | "updated"; reference: string; verified: true }
  | { status: "unchanged"; reference: string; verified: true }
> {
  const executor = await new ExecutorStore(macOsExecutorBackend()).load();
  authorizeDispatch?.();
  if (!executor) throw new Error("trusted_executor_not_enrolled");
  const intent =
    action === "save" ? "create" : action === "ensure" ? "ensure" : "update";
  const requested: Record<string, unknown> = existingRequestId
    ? { status: "owner_input_required", requestId: existingRequestId }
    : await mcpToolResult(session, "secrets_save", {
        secret_alias: alias,
        operation_id: operationId,
        intent,
        ...(intent === "create" ? { title: target } : { reference: target }),
      });
  const requestedReceiptStatus =
    intent === "ensure"
      ? ["unchanged", "updated"].includes(String(requested.status))
      : ["created", "updated"].includes(String(requested.status));
  if (requestedReceiptStatus)
    serviceAccountWriteReceipt(
      intent,
      requested,
      intent === "create" ? undefined : target,
    );
  if (
    requested.status === "owner_input_required" &&
    Object.keys(requested).sort().join(",") === "requestId,status" &&
    typeof requested.requestId === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(requested.requestId)
  ) {
    // Continue below with the owner-local executor.
  } else if (
    requested.status === "outcome_unknown" &&
    Object.keys(requested).sort().join(",") === "requestId,status"
  )
    throw new Error("Secret write outcome is unknown; do not retry blindly.");
  else if (!requestedReceiptStatus)
    throw new Error("Secret write was denied by the broker.");

  const requestId =
    existingRequestId ||
    (typeof requested.requestId === "string" ? requested.requestId : "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(requestId))
    throw new Error(
      "The cached secret write cannot be reconciled without its request ID.",
    );
  authorizeDispatch?.();
  const claimResponse = await localCompanionBroker(
    "/api/agent/secrets/local-companion/claim",
    { requestId, executorId: executor.executorId },
    session,
    executor,
  );
  if (!claimResponse.ok)
    throw new Error("The local companion request could not be claimed.");
  const claim: any = await claimResponse.json();
  if (
    claim.requestId !== requestId ||
    claim.alias !== alias ||
    claim.intent !== intent ||
    claim.target !== target ||
    claim.connectionId !== binding.connectionId ||
    claim.revision !== binding.connectionRevision
  )
    throw new Error("The local companion request binding changed.");
  if (claim.status === "saved")
    serviceAccountWriteReceipt(
      intent,
      claim,
      intent === "create" ? undefined : target,
    );
  if (!claim.claimed && !["fulfilling", "saved"].includes(String(claim.status)))
    throw new Error("The local companion request is not claimable.");
  if (
    typeof claim.operationId !== "string" ||
    !/^[A-Za-z0-9_-]{20,128}$/.test(claim.operationId) ||
    (operationId && claim.operationId !== operationId)
  )
    throw new Error("The local companion operation binding changed.");
  const effectiveOperationId = claim.operationId as string;

  authorizeDispatch?.();
  const reserveResponse = await localCompanionBroker(
    "/api/agent/secrets/local-companion/reserve",
    {
      requestId,
      executorId: executor.executorId,
      privateInputRequestId: requestId,
      alias,
      intent,
      operationId,
      connectionId: claim.connectionId,
      revision: claim.revision,
      target: claim.target,
      payloadDigest: await hash(value),
    },
    session,
    executor,
  );
  if (!reserveResponse.ok)
    throw new Error("The local companion write was not authorized.");
  const reservation: any = await reserveResponse.json();
  if (reservation.status === "saved")
    return serviceAccountWriteReceipt(
      intent,
      reservation,
      intent === "create" ? undefined : target,
    );
  if (reservation.status === "unknown")
    throw new Error("Secret write outcome is unknown; do not retry blindly.");
  if (reservation.status !== "reserved")
    throw new Error("The local companion write is already in progress.");

  const credentials = macOsKeychainProviderCredentials();
  const adapter = (() => {
    if (binding.providerMode === "bitwarden-password-manager")
      return new BitwardenPasswordManagerAdapter(binding, credentials);
    if (binding.providerMode === "lastpass")
      return new LastPassAdapter(binding, credentials);
    if (binding.providerMode === "onepassword-service-account")
      return new OnePasswordServiceAccountAdapter(
        binding,
        credentials,
        async (auth) => {
          const { createClient } = await import("@1password/sdk");
          const client = await createClient({
            auth,
            integrationName: "AgentSecret",
            integrationVersion: "3.0.0",
          });
          return guardServiceAccountClient(client, authorizeDispatch);
        },
      );
    throw new Error("The local companion provider is unsupported.");
  })();
  let receipt: {
    status: "created" | "updated" | "unchanged";
    reference: string;
    verified: true;
  };
  try {
    authorizeDispatch?.();
    if (intent === "create") {
      const created = await adapter.createSecret(target, value);
      receipt = {
        status: "created",
        reference: created.reference,
        verified: true,
      };
    } else if (intent === "ensure") {
      const ensured = await adapter.ensureField(target, value);
      receipt = {
        status: ensured.status,
        reference: target,
        verified: true,
      };
    } else {
      if (binding.providerMode === "onepassword-service-account") {
        const parsed = parseOnePasswordServiceAccountReference(target);
        await (adapter as OnePasswordServiceAccountAdapter).updateField(
          parsed.itemId,
          parsed.fieldId,
          value,
        );
      } else {
        await (
          adapter as BitwardenPasswordManagerAdapter | LastPassAdapter
        ).updateField(target, value);
      }
      receipt = { status: "updated", reference: target, verified: true };
    }
  } catch (error) {
    const ambiguous =
      error instanceof Error && error.message.endsWith("_outcome_unknown");
    await localCompanionBroker(
      "/api/agent/secrets/local-companion/complete",
      {
        requestId,
        executorId: executor.executorId,
        operationId: effectiveOperationId,
        status: "unknown",
      },
      session,
      executor,
    ).catch(() => undefined);
    if (ambiguous)
      throw new Error("Secret write outcome is unknown; do not retry blindly.");
    throw new Error("The local companion write failed before verification.");
  }
  const completeResponse = await localCompanionBroker(
    "/api/agent/secrets/local-companion/complete",
    {
      requestId,
      executorId: executor.executorId,
      operationId: effectiveOperationId,
      status: "saved",
      reference: receipt.reference,
      verified: true,
      ...(receipt.status === "unchanged" ? { resultStatus: "unchanged" } : {}),
      ...(intent === "ensure" && receipt.status === "updated"
        ? { resultStatus: "updated" }
        : {}),
    },
    session,
    executor,
  );
  if (!completeResponse.ok)
    throw new Error(
      "The provider write completed but the broker receipt is unknown; do not retry blindly.",
    );
  const completed: unknown = await completeResponse.json();
  if (!completed || typeof completed !== "object" || Array.isArray(completed))
    throw new Error(
      "The provider write completed but the broker receipt is invalid; do not retry blindly.",
    );
  const completedReceipt = serviceAccountWriteReceipt(
    intent,
    completed as Record<string, unknown>,
    receipt.reference,
  );
  if (completedReceipt.status !== receipt.status)
    throw new Error(
      "The provider write completed but the broker receipt disagreed; do not retry blindly.",
    );
  return receipt;
}

async function fulfillExistingServiceAccountRequest(
  session: Awaited<ReturnType<typeof credentials>>,
  requestId: string,
): Promise<
  | { status: "created" | "updated"; reference: string; verified: true }
  | { status: "unchanged"; reference: string; verified: true }
  | { status: "deleted"; reference: string; verified: true }
> {
  const executor = await new ExecutorStore(macOsExecutorBackend()).load();
  if (!executor) throw new Error("trusted_executor_not_enrolled");
  const claimResponse = await localCompanionBroker(
    "/api/agent/secrets/local-companion/claim",
    { requestId, executorId: executor.executorId },
    session,
    executor,
  );
  if (!claimResponse.ok)
    throw new Error("The local companion request could not be claimed.");
  const claim: any = await claimResponse.json();
  if (
    claim.requestId !== requestId ||
    typeof claim.alias !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(claim.alias) ||
    !["create", "update", "ensure", "delete"].includes(claim.intent) ||
    typeof claim.target !== "string" ||
    typeof claim.connectionId !== "string" ||
    !Number.isSafeInteger(claim.revision)
  )
    throw new Error("The local companion request binding changed.");
  if (claim.status === "unknown")
    throw new Error("Secret write outcome is unknown; do not retry blindly.");
  const action =
    claim.intent === "create"
      ? "save"
      : claim.intent === "delete"
        ? "delete"
        : claim.intent;
  if (claim.status === "saved") {
    if (action === "delete")
      return serviceAccountDeleteReceipt(claim, claim.target);
    return serviceAccountWriteReceipt(
      action === "save" ? "create" : action,
      claim,
      claim.intent === "create" ? undefined : claim.target,
    );
  }
  if (!claim.claimed && claim.status !== "fulfilling")
    throw new Error("The local companion request is not claimable.");
  const binding = await serviceAccountBindingForAlias(
    session,
    claim.alias,
    claim.intent === "create"
      ? "create"
      : claim.intent === "delete"
        ? "delete"
        : "update",
  );
  if (
    !binding ||
    binding.connectionId !== claim.connectionId ||
    binding.connectionRevision !== claim.revision
  )
    throw new Error("The local companion provider binding changed.");
  if (action === "delete") {
    await confirmExactSecretDeletion(claim.target);
    const receipt = await fulfillServiceAccountDelete(
      session,
      binding,
      claim.alias,
      claim.target,
      claim.operationId,
    );
    const completeResponse = await localCompanionBroker(
      "/api/agent/secrets/local-companion/complete",
      {
        requestId,
        executorId: executor.executorId,
        operationId: claim.operationId,
        status: "saved",
        reference: claim.target,
        verified: true,
      },
      session,
      executor,
    );
    if (!completeResponse.ok)
      throw new Error(
        "The provider deletion completed but the broker receipt is unknown; do not retry blindly.",
      );
    serviceAccountDeleteReceipt(await completeResponse.json(), claim.target);
    return receipt;
  }
  requireInteractiveSecretTerminal();
  const value = await readSecretInput();
  return fulfillServiceAccountWrite(
    session,
    binding,
    claim.alias,
    action,
    claim.target,
    claim.operationId,
    value,
    requestId,
  );
}

async function fulfillServiceAccountDelete(
  session: Awaited<ReturnType<typeof credentials>>,
  binding: ProviderCredentialBinding,
  alias: string,
  reference: string,
  operationId: string,
): Promise<{ status: "deleted"; reference: string; verified: true }> {
  const executor = await new ExecutorStore(macOsExecutorBackend()).load();
  if (!executor) throw new Error("trusted_executor_not_enrolled");
  const reserveResponse = await localCompanionBroker(
    "/api/agent/secrets/local-companion/delete-reserve",
    {
      alias,
      executorId: executor.executorId,
      operationId,
      connectionId: binding.connectionId,
      revision: binding.connectionRevision,
      reference,
    },
    session,
    executor,
  );
  if (!reserveResponse.ok)
    throw new Error("The local companion deletion was not authorized.");
  const reservation: unknown = await reserveResponse.json();
  if (
    !reservation ||
    typeof reservation !== "object" ||
    Array.isArray(reservation)
  )
    throw new Error("The local companion deletion receipt is invalid.");
  const reservationResult = reservation as Record<string, unknown>;
  if (reservationResult.status === "saved")
    return serviceAccountDeleteReceipt(reservationResult, reference);
  if (reservationResult.status === "unknown")
    throw new Error("Delete outcome is unknown; do not retry blindly.");
  if (reservationResult.status !== "reserved")
    throw new Error("The local companion deletion is already in progress.");
  const adapter = new OnePasswordServiceAccountAdapter(
    binding,
    macOsKeychainProviderCredentials(),
  );
  let ambiguous = false;
  try {
    const parsed = parseOnePasswordServiceAccountReference(reference);
    await adapter.deleteCustomField(parsed.itemId, parsed.fieldId);
  } catch (error) {
    ambiguous =
      error instanceof Error && error.message.endsWith("_outcome_unknown");
    await localCompanionBroker(
      "/api/agent/secrets/local-companion/delete-complete",
      {
        executorId: executor.executorId,
        operationId,
        reference,
        status: "unknown",
      },
      session,
      executor,
    ).catch(() => undefined);
    if (ambiguous)
      throw new Error("Delete outcome is unknown; do not retry blindly.");
    throw new Error("The local companion deletion failed before verification.");
  }
  const completeResponse = await localCompanionBroker(
    "/api/agent/secrets/local-companion/delete-complete",
    {
      executorId: executor.executorId,
      operationId,
      reference,
      status: "saved",
    },
    session,
    executor,
  );
  if (!completeResponse.ok)
    throw new Error(
      "The provider deletion completed but the broker receipt is unknown; do not retry blindly.",
    );
  return serviceAccountDeleteReceipt(await completeResponse.json(), reference);
}

async function companionBindingForAlias(
  session: Awaited<ReturnType<typeof credentials>>,
  alias: string,
  expectedMode:
    "bitwarden-password-manager" | "onepassword-service-account" | "lastpass",
): Promise<{
  binding: ProviderCredentialBinding;
  read: boolean;
} | null> {
  let response: Response;
  try {
    response = await broker(
      "/mcp",
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "list_available_secrets", arguments: {} },
      },
      session,
    );
  } catch {
    operation.signal.throwIfAborted();
    throw new Error("bitwarden_password_manager_binding_unavailable");
  }
  if (!response.ok)
    throw new Error("bitwarden_password_manager_binding_unavailable");
  let envelope: unknown;
  try {
    envelope = await response.json();
  } catch {
    throw new Error("bitwarden_password_manager_binding_unavailable");
  }
  if (
    !envelope ||
    typeof envelope !== "object" ||
    Array.isArray(envelope) ||
    (envelope as { jsonrpc?: unknown }).jsonrpc !== "2.0" ||
    (envelope as { id?: unknown }).id !== 1 ||
    Object.hasOwn(envelope, "error")
  )
    throw new Error("bitwarden_password_manager_binding_unavailable");
  const result = (envelope as { result?: unknown }).result;
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new Error("bitwarden_password_manager_binding_unavailable");
  const content = (result as { content?: unknown }).content;
  if (
    !Array.isArray(content) ||
    content.length !== 1 ||
    !content[0] ||
    typeof content[0] !== "object" ||
    (content[0] as { type?: unknown }).type !== "text" ||
    typeof (content[0] as { text?: unknown }).text !== "string"
  )
    throw new Error("bitwarden_password_manager_binding_unavailable");
  let payload: unknown;
  try {
    payload = JSON.parse((content[0] as { text: string }).text);
  } catch {
    throw new Error("bitwarden_password_manager_binding_unavailable");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload))
    throw new Error("bitwarden_password_manager_binding_unavailable");
  const entries = (payload as { available_secrets?: unknown })
    .available_secrets;
  if (!Array.isArray(entries))
    throw new Error("bitwarden_password_manager_binding_unavailable");
  const matches = entries.filter(
    (entry) =>
      !!entry &&
      typeof entry === "object" &&
      !Array.isArray(entry) &&
      (entry as { alias?: unknown }).alias === alias.toUpperCase(),
  );
  if (matches.length !== 1)
    throw new Error("bitwarden_password_manager_binding_unavailable");
  const entry = matches[0] as Record<string, unknown>;
  const capabilities = entry.provider_capabilities;
  const binding = entry.companion_binding;
  if (
    entry.connection_status === "ready" &&
    entry.provider_mode !== expectedMode
  )
    return null;
  if (
    entry.connection_status !== "ready" ||
    entry.provider_mode !== expectedMode ||
    !capabilities ||
    typeof capabilities !== "object" ||
    Array.isArray(capabilities) ||
    (capabilities as { status?: unknown }).status !== "requires-companion" ||
    !binding ||
    typeof binding !== "object" ||
    Array.isArray(binding) ||
    Object.keys(binding).sort().join(",") !==
      "connection_id,connection_revision" ||
    typeof (binding as { connection_id?: unknown }).connection_id !==
      "string" ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(
      (binding as { connection_id: string }).connection_id,
    ) ||
    !Number.isSafeInteger(
      (binding as { connection_revision?: unknown }).connection_revision,
    ) ||
    (binding as { connection_revision: number }).connection_revision < 1
  )
    throw new Error("bitwarden_password_manager_binding_unavailable");
  return {
    binding: {
      server: session.server,
      tenant: session.tenant,
      connectionId: (binding as { connection_id: string }).connection_id,
      connectionRevision: (binding as { connection_revision: number })
        .connection_revision,
      providerMode: expectedMode,
    },
    read: (capabilities as { read: boolean }).read,
  };
}

async function resolveBitwardenPasswordManagerFind(
  session: Awaited<ReturnType<typeof credentials>>,
  alias: string,
  reference: string,
  currentBinding?: ProviderCredentialBinding,
): Promise<{ status: "available"; provider: string; reference: string }> {
  const binding =
    currentBinding ||
    (
      await companionBindingForAlias(
        session,
        alias,
        "bitwarden-password-manager",
      )
    )?.binding;
  if (!binding)
    throw new Error("bitwarden_password_manager_binding_unavailable");
  const adapter = new BitwardenPasswordManagerAdapter(
    binding,
    macOsKeychainProviderCredentials(),
  );
  await adapter.withResolvedField(reference, async () => undefined);
  return {
    status: "available",
    provider: "bitwarden-password-manager",
    reference,
  };
}

async function resolveOnePasswordServiceAccountFind(
  session: Awaited<ReturnType<typeof credentials>>,
  alias: string,
  reference: string,
  currentBinding?: ProviderCredentialBinding,
): Promise<{ status: "available"; provider: string; reference: string }> {
  const match =
    /^([A-Za-z0-9_-]{1,128})#\/fields\/([A-Za-z0-9_-]{1,128})$/.exec(reference);
  if (!match) throw new Error("onepassword_service_account_reference_invalid");
  const binding =
    currentBinding ||
    (
      await companionBindingForAlias(
        session,
        alias,
        "onepassword-service-account",
      )
    )?.binding;
  if (!binding)
    throw new Error("onepassword_service_account_binding_unavailable");
  const adapter = new OnePasswordServiceAccountAdapter(
    binding,
    macOsKeychainProviderCredentials(),
  );
  await adapter.withResolvedField(match[1]!, match[2]!, async () => undefined);
  return {
    status: "available",
    provider: "onepassword-service-account",
    reference,
  };
}

async function resolveLastPassFind(
  session: Awaited<ReturnType<typeof credentials>>,
  alias: string,
  reference: string,
  currentBinding?: ProviderCredentialBinding,
): Promise<{ status: "available"; provider: string; reference: string }> {
  const binding =
    currentBinding ||
    (await companionBindingForAlias(session, alias, "lastpass"))?.binding;
  if (!binding) throw new Error("lastpass_binding_unavailable");
  const adapter = new LastPassAdapter(
    binding,
    macOsKeychainProviderCredentials(),
  );
  await adapter.withResolvedField(reference, async () => undefined);
  return { status: "available", provider: "lastpass", reference };
}

async function localCompanionResponse(
  session: Awaited<ReturnType<typeof credentials>>,
  request: unknown,
  remoteResponse: unknown,
  expectedMode:
    "bitwarden-password-manager" | "onepassword-service-account" | "lastpass",
  consume?: (value: string) => Promise<void>,
): Promise<string | null> {
  if (
    !request ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    !remoteResponse ||
    typeof remoteResponse !== "object" ||
    Array.isArray(remoteResponse)
  )
    return null;
  const requestRecord = request as Record<string, unknown>;
  const responseRecord = remoteResponse as Record<string, unknown>;
  const params = requestRecord.params;
  const result = responseRecord.result;
  if (
    requestRecord.jsonrpc !== "2.0" ||
    requestRecord.method !== "tools/call" ||
    (typeof requestRecord.id !== "string" &&
      typeof requestRecord.id !== "number") ||
    responseRecord.jsonrpc !== "2.0" ||
    responseRecord.id !== requestRecord.id ||
    Object.hasOwn(responseRecord, "error") ||
    !params ||
    typeof params !== "object" ||
    Array.isArray(params) ||
    (params as { name?: unknown }).name !== "secrets_find" ||
    !result ||
    typeof result !== "object" ||
    Array.isArray(result) ||
    (result as { isError?: unknown }).isError !== true
  )
    return null;
  const content = (result as { content?: unknown }).content;
  if (
    !Array.isArray(content) ||
    content.length !== 1 ||
    !content[0] ||
    typeof content[0] !== "object" ||
    (content[0] as { type?: unknown }).type !== "text" ||
    (content[0] as { text?: unknown }).text !== "secret_store_unavailable"
  )
    return null;
  const argumentsValue = (params as { arguments?: unknown }).arguments;
  if (
    !argumentsValue ||
    typeof argumentsValue !== "object" ||
    Array.isArray(argumentsValue)
  )
    return null;
  const findArgs = argumentsValue as Record<string, unknown>;
  if (
    Object.keys(findArgs).sort().join(",") !== "reference,secret_alias" ||
    typeof findArgs.secret_alias !== "string" ||
    !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(findArgs.secret_alias) ||
    typeof findArgs.reference !== "string"
  )
    return null;
  const companion = await companionBindingForAlias(
    session,
    findArgs.secret_alias,
    expectedMode,
  );
  if (!companion || !companion.read) return null;
  if (consume) {
    if (expectedMode === "bitwarden-password-manager") {
      await new BitwardenPasswordManagerAdapter(
        companion.binding,
        macOsKeychainProviderCredentials(),
      ).withResolvedField(findArgs.reference, consume);
    } else if (expectedMode === "onepassword-service-account") {
      const parsed = parseOnePasswordServiceAccountReference(
        findArgs.reference,
      );
      await new OnePasswordServiceAccountAdapter(
        companion.binding,
        macOsKeychainProviderCredentials(),
      ).withResolvedField(parsed.itemId, parsed.fieldId, consume);
    } else {
      await new LastPassAdapter(
        companion.binding,
        macOsKeychainProviderCredentials(),
      ).withResolvedField(findArgs.reference, consume);
    }
    return "consumed";
  }
  const safeResult =
    expectedMode === "bitwarden-password-manager"
      ? await resolveBitwardenPasswordManagerFind(
          session,
          findArgs.secret_alias,
          findArgs.reference,
          companion.binding,
        )
      : expectedMode === "onepassword-service-account"
        ? await resolveOnePasswordServiceAccountFind(
            session,
            findArgs.secret_alias,
            findArgs.reference,
            companion.binding,
          )
        : await resolveLastPassFind(
            session,
            findArgs.secret_alias,
            findArgs.reference,
            companion.binding,
          );
  return JSON.stringify({
    jsonrpc: "2.0",
    id: requestRecord.id,
    result: {
      content: [{ type: "text", text: JSON.stringify(safeResult) }],
    },
  });
}

async function resolveBrowserSecret(
  session: Awaited<ReturnType<typeof credentials>>,
  alias: string,
  reference: string,
): Promise<string> {
  const request = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "secrets_find",
      arguments: { secret_alias: alias, reference },
    },
  };
  const response = await broker("/mcp", request, session);
  if (!response.ok) throw new Error("browser_secret_unavailable");
  let envelope: unknown;
  try {
    envelope = await response.json();
  } catch {
    throw new Error("browser_secret_unavailable");
  }
  for (const mode of [
    "bitwarden-password-manager",
    "onepassword-service-account",
    "lastpass",
  ] as const) {
    let resolved: string | undefined;
    const accepted = await localCompanionResponse(
      session,
      request,
      envelope,
      mode,
      async (value) => {
        resolved = value;
      },
    );
    if (accepted !== null && typeof resolved === "string" && resolved.length)
      return resolved;
  }
  throw new Error("browser_provider_runtime_unsupported");
}

async function storeBrowserCapture(
  session: Awaited<ReturnType<typeof credentials>>,
  alias: string,
  reference: string,
  value: string,
  authorizeDispatch: () => void,
): Promise<{ reference: string; verified: boolean }> {
  const companion = await companionBindingForAlias(
    session,
    alias,
    "onepassword-service-account",
  );
  if (!companion || !companion.read)
    throw new Error("browser_capture_provider_unsupported");
  const operationId = random(32);
  authorizeDispatch();
  const requested = await mcpToolResult(session, "secrets_save", {
    secret_alias: alias.toUpperCase(),
    operation_id: operationId,
    intent: "update",
    reference,
  });
  if (
    requested.status !== "owner_input_required" ||
    typeof requested.requestId !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/u.test(requested.requestId)
  ) {
    if (requested.status === "outcome_unknown")
      throw new Error("browser_capture_outcome_unknown");
    throw new Error("browser_capture_write_denied");
  }
  try {
    const receipt = await fulfillServiceAccountWrite(
      session,
      companion.binding,
      alias.toUpperCase(),
      "update",
      reference,
      operationId,
      value,
      requested.requestId,
      authorizeDispatch,
    );
    return { reference: receipt.reference, verified: receipt.verified };
  } catch (error) {
    if (error instanceof Error && error.message === "grant_expired")
      throw error;
    throw new Error("browser_capture_store_failed");
  }
}

async function brokerProxyWithCapability(value: unknown) {
  const requestBody = JSON.stringify(value);
  if (Buffer.byteLength(requestBody, "utf8") > 60 * 1024)
    throw new Error("Request exceeds size limit.");
  const session = await credentials();
  const issued = await broker("/api/agent/proxy-capabilities", value, session);
  if (!issued.ok) return issued;

  let response: unknown;
  try {
    const issueBody = await issued.text();
    if (Buffer.byteLength(issueBody, "utf8") > 4096) throw new Error();
    response = JSON.parse(issueBody);
  } catch {
    throw new Error("Broker returned an invalid proxy capability response.");
  }
  if (
    !response ||
    typeof response !== "object" ||
    Array.isArray(response) ||
    typeof (response as { capability?: unknown }).capability !== "string" ||
    !Number.isSafeInteger((response as { expiresAt?: unknown }).expiresAt) ||
    (response as { expiresAt: number }).expiresAt <=
      Math.floor(Date.now() / 1000)
  )
    throw new Error("Broker returned an invalid proxy capability response.");

  const capability = (response as { capability: string }).capability;
  const parts = capability.split(".");
  if (
    parts.length !== 3 ||
    parts[0] !== "aspc1" ||
    parts[1] !== session.tenant ||
    !/^[A-Za-z0-9_-]{43}$/.test(parts[2])
  )
    throw new Error("Broker returned an invalid proxy capability response.");

  operation.signal.throwIfAborted();
  proxyCapabilityRedemptionStarted = true;
  return fetch(session.server + "/proxy/capability", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "AgentSecret " + capability,
    },
    body: requestBody,
    redirect: "error",
    signal: requestSignal(20000),
  });
}
function requireInteractiveSecretTerminal() {
  const input = process.stdin;
  if (
    !input.isTTY ||
    typeof input.setRawMode !== "function" ||
    !process.stderr.isTTY
  )
    throw new Error(
      "Secret input requires an interactive terminal on stdin and stderr; piped input is refused.",
    );
  return input;
}

async function confirmExactSecretDeletion(reference: string): Promise<void> {
  operation.signal.throwIfAborted();
  const input = requireInteractiveSecretTerminal();
  const prompt = createInterface({
    input,
    output: process.stderr,
    terminal: true,
  });
  process.stderr.write(
    `Delete the exact vault field ${reference}? Type the full reference to confirm: `,
  );
  try {
    const answer = await new Promise<string>((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        operation.signal.removeEventListener("abort", onAbort);
        prompt.removeListener("SIGINT", onSigint);
        prompt.removeListener("close", onClose);
      };
      const settle = (error?: Error, answer?: string) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (error) reject(error);
        else resolve(answer ?? "");
      };
      const onAbort = () => {
        settle(operation.signal.reason || new Error("Operation cancelled."));
        prompt.close();
      };
      const onSigint = () => {
        signalExitCode = 130;
        const reason = new Error("Operation cancelled by Ctrl+C.");
        operation.abort(reason);
        settle(reason);
        prompt.close();
      };
      const onClose = () =>
        settle(
          new Error("Deletion confirmation cancelled because input closed."),
        );
      prompt.once("SIGINT", onSigint);
      prompt.once("close", onClose);
      operation.signal.addEventListener("abort", onAbort, { once: true });
      prompt.question("", (line) => {
        settle(undefined, line);
      });
    });
    if (answer !== reference)
      throw new Error(
        "Deletion cancelled because the reference did not match.",
      );
  } finally {
    prompt.close();
    process.stderr.write("\n");
  }
}
async function readSecretInput(): Promise<string> {
  operation.signal.throwIfAborted();
  const input = requireInteractiveSecretTerminal();
  const previousRawMode = input.isRaw;
  const decoder = new StringDecoder("utf8");
  let value = "";
  let escapeState:
    "none" | "introducer" | "csi" | "ss3" | "osc" | "osc_escape" = "none";
  let escapeSequence = "";
  let bracketedPaste = false;
  process.stderr.write("\u001b[?2004hSecret value (hidden): ");
  input.setRawMode(true);
  input.resume();
  return new Promise<string>((resolve, reject) => {
    const onAbort = () => {
      cleanup();
      reject(operation.signal.reason || new Error("Operation cancelled."));
    };
    const cleanup = () => {
      input.off("data", onData);
      operation.signal.removeEventListener("abort", onAbort);
      input.setRawMode(previousRawMode);
      input.pause();
      process.stderr.write("\u001b[?2004l\n");
    };
    const onData = (chunk: Buffer) => {
      const text = decoder.write(chunk);
      for (const char of text) {
        if (char === "\u0003" || char === "\u0004") {
          cleanup();
          reject(new Error("Secret entry cancelled."));
          return;
        }
        if (escapeState === "introducer") {
          escapeState =
            char === "["
              ? "csi"
              : char === "O"
                ? "ss3"
                : char === "]"
                  ? "osc"
                  : "none";
          escapeSequence = char === "[" ? "\u001b[" : "";
          continue;
        }
        if (escapeState === "csi") {
          escapeSequence += char;
          if (char >= "@" && char <= "~") {
            if (escapeSequence === "\u001b[200~") bracketedPaste = true;
            if (escapeSequence === "\u001b[201~") bracketedPaste = false;
            escapeState = "none";
            escapeSequence = "";
          }
          continue;
        }
        if (escapeState === "ss3") {
          escapeState = "none";
          continue;
        }
        if (escapeState === "osc") {
          if (char === "\u0007") escapeState = "none";
          else if (char === "\u001b") escapeState = "osc_escape";
          continue;
        }
        if (escapeState === "osc_escape") {
          escapeState = char === "\\" ? "none" : "osc";
          continue;
        }
        if (char === "\u001b") {
          escapeState = "introducer";
          continue;
        }
        if (char === "\r" || char === "\n") {
          if (bracketedPaste) {
            value += char === "\r" ? "\n" : char;
            continue;
          }
          cleanup();
          resolve(value);
          return;
        }
        if (char === "\u007f" || char === "\b") {
          value = Array.from(value).slice(0, -1).join("");
          continue;
        }
        if (char >= " " && char !== "\u007f") value += char;
      }
      if (Buffer.byteLength(value, "utf8") > 8192) {
        cleanup();
        reject(new Error("Secret value exceeds the 8192-byte limit."));
      }
    };
    input.on("data", onData);
    operation.signal.addEventListener("abort", onAbort, { once: true });
  });
}
async function main() {
  if (command === "help" || command === "--help" || command === "-h") {
    console.log(
      "agentsecret login --server <HTTPS origin> [--device] [--write] [--tenant <id>] [--aliases A,B]\nagentsecret ensure [--server <HTTPS origin>] [--device]   # enroll if needed, then verify the broker accepts the session\nagentsecret status [--remote [--alias <alias>]]   # with --alias, also check current policy/connection and declared read capability\nagentsecret request --alias <alias> --url <HTTPS URL> [--method POST] [--data JSON | --stdin]\n--stdin reads bounded JSON {headers?, body?}; caller headers are filtered and protected auth/transport headers are refused.\nagentsecret secrets list   # list authorized aliases, destination/method policy, credential sink, and scoped owner write grants\nagentsecret secrets find --alias <alias> [--store <store>] [--reference <ref> | --binding <JSON> [--inputs <JSON>] | --title <owner-pinned-title> | --login-lookup <JSON>] [--optional]   # selectors must match the alias owner's current binding\nsecret_ref binding: {secret_ref:{type?:secret_ref, store?, object_id, field_path?}}; input form uses {secret_ref_input:<name>} plus --inputs containing only that named ref; onepassword-connect maps an exact object ID and /fields/<field-id>/value JSON Pointer to its owner-bound Connect reference; named_secret and login_lookup support direct or named-input owner-pinned Connect locators; env_var is local-only and rejected locally; BWP, 1Password service-account, and LastPass exact references use the local companion only after cloud authorization; unsupported companion selectors remain unavailable; BWS refs require UUIDs\nlogin-lookup JSON: kind=login_lookup, title, username, unique uris[], fieldId, optional fieldPath\nagentsecret secrets save --alias <alias> --title <title>   # hidden terminal input; requires --write approval\nagentsecret secrets update --alias <alias> --reference <ref>   # hidden terminal input; exact owner-bound ref only\nagentsecret secrets ensure --alias <alias> --reference <ref>   # owner enters value in dashboard; comparison stays private\nagentsecret secrets delete --alias <alias> --reference <ref>   # exact owner-pinned field; interactive confirmation required\nUse --new-operation only after checking the vault for an unresolved write.\nagentsecret mcp [--server <origin>]   # authenticated stdio bridge with exact local BWP/1Password service-account/LastPass read fallbacks\nagentsecret logout [--remote]   # --remote revokes this agent session before clearing local state\nCI: set AGENTSECRET_SERVER and configure workload identity. Keys stay in memory.\nStrict mode does not inject vault credentials into native commands.",
    );
    console.log(
      "agentsecret secrets fulfill --request-id <id>   # complete an existing pending service-account request locally; hidden value prompt",
    );
    console.log(
      "agentsecret browser identity   # create or show the public trusted-executor identity in its dedicated macOS Keychain item; no private key is output",
    );
    console.log(
      "agentsecret browser act --grant <id> --kind <fill|totp|capture|verify|ensure> --origin <https origin> --selector <css> --reference <ref> [--url <page url>] [--receipt-dir <dir>]   # consume one owner-issued grant against the verified Chrome installation; output is a value-free receipt",
    );
    console.log(
      "agentsecret run browser --grant <id> --kind <fill|totp|capture|verify|ensure> --origin <https origin> --selector <css> --reference <ref> [--url <page url>] [--receipt-dir <dir>]   # managed-run protected browser action behind the qualified runtime gate; output is a value-free receipt",
    );
    console.log(
      "agentsecret providers bwp bind-profile --alias <alias> --fastflow-app-name <profile>   # ensure and bind a Fastflow Bitwarden profile locally after owner confirmation; identity stays in Keychain\nagentsecret providers op-sa configure --alias <alias>   # bind a scoped 1Password service-account token and vault locally; token stays in Keychain\nagentsecret providers lastpass configure --alias <alias>   # bind a private LastPass test-profile directory and account identity; authenticate it directly with lpass\nFor exact companion references, hosted secrets find and stdio MCP use the local provider only after the cloud authorizes the same alias/reference; output contains only status and reference.",
    );
    return;
  }
  if (command === "login") {
    await login(
      serverOrigin(
        option("server") ||
          process.env.AGENTSECRET_SERVER ||
          load()?.server ||
          "",
      ),
      args.includes("--device"),
      args.includes("--write"),
    );
    return;
  }
  if (command === "ensure") {
    let stored: ReturnType<typeof load>;
    try {
      stored = load();
    } catch {
      console.log(JSON.stringify({ status: "invalid_local_session" }));
      process.exitCode = 1;
      return;
    }
    if (stored && !validLocalSession(stored)) {
      console.log(JSON.stringify({ status: "invalid_local_session" }));
      process.exitCode = 1;
      return;
    }
    try {
      const session = await credentials();
      const remoteVerification = await remoteAgentStatus(session);
      if (remoteVerification === "authenticated") {
        console.log(
          JSON.stringify({
            status: "ready",
            server: session.server,
            expiresAt: session.expiresAt,
            remoteVerification,
          }),
        );
      } else {
        console.log(
          JSON.stringify({
            status: "not_ready",
            reason:
              remoteVerification === "rejected"
                ? "remote_session_rejected"
                : "remote_status_unavailable",
          }),
        );
        process.exitCode = 1;
      }
    } catch {
      operation.signal.throwIfAborted();
      console.log(
        JSON.stringify({
          status: "setup_needed",
          reason: "authentication_required_or_unavailable",
        }),
      );
      process.exitCode = 1;
    }
    return;
  }
  if (
    command === "providers" &&
    args[0] === "bwp" &&
    args[1] === "bind-profile"
  ) {
    args.splice(0, 2);
    const alias = option("alias");
    const fastflowAppName = option("fastflow-app-name");
    if (
      !process.stdin.isTTY ||
      !process.stderr.isTTY ||
      !alias ||
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias) ||
      !fastflowAppName ||
      !/^[A-Za-z0-9_-]{1,80}$/.test(fastflowAppName) ||
      args.length !== 4 ||
      args.filter((arg) => arg === "--alias").length !== 1 ||
      args.filter((arg) => arg === "--fastflow-app-name").length !== 1 ||
      args.some(
        (arg) =>
          !["--alias", "--fastflow-app-name", alias, fastflowAppName].includes(
            arg,
          ),
      )
    )
      throw new Error(
        "Use an interactive terminal: providers bwp bind-profile --alias <alias> --fastflow-app-name <profile>.",
      );

    const session = await credentials();
    const companion = await companionBindingForAlias(
      session,
      alias,
      "bitwarden-password-manager",
    );
    const binding = companion?.binding;
    if (!binding)
      throw new Error("bitwarden_password_manager_binding_unavailable");
    const identity = await inspectFastflowBitwardenProfile(fastflowAppName);
    const profileInput = createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });
    let answer: string;
    try {
      process.stderr.write(
        `Fastflow profile identity: ${identity.userEmail} (${identity.userId})\n` +
          `Bind it to AgentSecret alias ${alias.toUpperCase()}? Confirm only if this is the isolated test account. Type YES: `,
      );
      answer = await new Promise<string>((resolve) => {
        profileInput.question("", resolve);
      });
    } finally {
      profileInput.close();
    }
    if (answer.trim() !== "YES")
      throw new Error("bitwarden_password_manager_profile_binding_cancelled");

    await macOsKeychainProviderCredentials().put(
      binding,
      serializeFastflowBitwardenProfile(fastflowAppName, identity),
    );
    console.log(
      JSON.stringify({
        status: "profile_bound",
        alias: alias.toUpperCase(),
        provider_mode: "bitwarden-password-manager",
        connection_revision: binding.connectionRevision,
      }),
    );
    return;
  }
  if (
    command === "providers" &&
    args[0] === "op-sa" &&
    args[1] === "configure"
  ) {
    args.splice(0, 2);
    const alias = option("alias");
    if (
      !process.stdin.isTTY ||
      !process.stderr.isTTY ||
      !alias ||
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias) ||
      args.length !== 2 ||
      args.filter((arg) => arg === "--alias").length !== 1 ||
      args.some((arg) => !["--alias", alias].includes(arg))
    )
      throw new Error(
        "Use an interactive terminal: providers op-sa configure --alias <alias>.",
      );
    const session = await credentials();
    const companion = await companionBindingForAlias(
      session,
      alias,
      "onepassword-service-account",
    );
    const binding = companion?.binding;
    if (!binding)
      throw new Error("onepassword_service_account_binding_unavailable");
    const prompt = createInterface({
      input: process.stdin,
      output: process.stderr,
    });
    let vaultId: string;
    try {
      vaultId = await new Promise<string>((resolve) => {
        prompt.question("Dedicated test vault ID: ", resolve);
      });
    } finally {
      prompt.close();
    }
    const token = await readSecretInput();
    const nextProfile = serializeOnePasswordServiceAccountProfile(
      token,
      vaultId.trim(),
    );
    const credentialStore = macOsKeychainProviderCredentials();
    const priorProfile = await credentialStore.get(binding);
    await credentialStore.put(binding, nextProfile);
    try {
      const adapter = new OnePasswordServiceAccountAdapter(
        binding,
        credentialStore,
      );
      await adapter.verifyVaultAccess();
    } catch {
      if (priorProfile === undefined) await credentialStore.delete(binding);
      else await credentialStore.put(binding, priorProfile);
      throw new Error("onepassword_service_account_vault_access_failed");
    }
    console.log(
      JSON.stringify({
        status: "profile_bound",
        alias: alias.toUpperCase(),
        provider_mode: "onepassword-service-account",
        connection_revision: binding.connectionRevision,
      }),
    );
    return;
  }
  if (
    command === "providers" &&
    args[0] === "lastpass" &&
    args[1] === "configure"
  ) {
    args.splice(0, 2);
    const alias = option("alias");
    if (
      !process.stdin.isTTY ||
      !process.stderr.isTTY ||
      !alias ||
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias) ||
      args.length !== 2 ||
      args.filter((arg) => arg === "--alias").length !== 1 ||
      args.some((arg) => !["--alias", alias].includes(arg))
    )
      throw new Error(
        "Use an interactive terminal: providers lastpass configure --alias <alias>.",
      );
    const session = await credentials();
    const companion = await companionBindingForAlias(
      session,
      alias,
      "lastpass",
    );
    const binding = companion?.binding;
    if (!binding) throw new Error("lastpass_binding_unavailable");
    const profileRoot = join(
      homedir(),
      ".local",
      "share",
      "agentsecret",
      "lastpass",
    );
    const profileKey = createHash("sha256")
      .update(JSON.stringify(binding))
      .digest("hex");
    const profileHome = join(profileRoot, profileKey);
    const prompt = createInterface({
      input: process.stdin,
      output: process.stderr,
    });
    let userEmail: string;
    let answer: string;
    try {
      userEmail = await new Promise<string>((resolve) => {
        prompt.question("Isolated LastPass test account email: ", resolve);
      });
      process.stderr.write(
        `This binds a dedicated LPASS_HOME to AgentSecret alias ${alias.toUpperCase()}. Confirm only if the account is the isolated test account. Type YES: `,
      );
      answer = await new Promise<string>((resolve) => {
        prompt.question("", resolve);
      });
    } finally {
      prompt.close();
    }
    if (answer.trim() !== "YES")
      throw new Error("lastpass_profile_binding_cancelled");
    mkdirSync(profileHome, { recursive: true, mode: 0o700 });
    chmodSync(profileHome, 0o700);
    const profileInfo = lstatSync(profileHome);
    if (
      !profileInfo.isDirectory() ||
      (profileInfo.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" &&
        profileInfo.uid !== process.getuid())
    )
      throw new Error("lastpass_profile_invalid");
    const credentialStore = macOsKeychainProviderCredentials();
    if (await credentialStore.get(binding))
      throw new Error("lastpass_profile_already_configured");
    await credentialStore.put(
      binding,
      serializeLastPassProfile(profileHome, userEmail.trim()),
    );
    console.log(
      JSON.stringify({
        status: "profile_bound_setup_required",
        alias: alias.toUpperCase(),
        provider_mode: "lastpass",
        connection_revision: binding.connectionRevision,
        profile_home: profileHome,
      }),
    );
    return;
  }
  if (command === "status") {
    const hasAlias = args.includes("--alias");
    const requestedAlias = option("alias");
    if (
      hasAlias &&
      (!args.includes("--remote") ||
        !requestedAlias ||
        requestedAlias.startsWith("--") ||
        !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(requestedAlias))
    ) {
      console.log(JSON.stringify({ status: "invalid_arguments" }));
      process.exitCode = 2;
      return;
    }
    let stored: ReturnType<typeof load>;
    try {
      stored = load();
    } catch {
      console.log(JSON.stringify({ status: "invalid_local_session" }));
      process.exitCode = 1;
      return;
    }
    if (!stored) {
      console.log(
        JSON.stringify({
          status: "setup_needed",
          ...(requestedAlias
            ? {
                remoteVerification: "not_checked",
                alias: requestedAlias.toUpperCase(),
                aliasVerification: "unavailable",
              }
            : {}),
        }),
      );
      if (requestedAlias) process.exitCode = 1;
      return;
    }
    if (
      typeof stored.server !== "string" ||
      typeof stored.accessToken !== "string" ||
      !stored.accessToken ||
      typeof stored.tenant !== "string" ||
      !Number.isSafeInteger(stored.expiresAt) ||
      stored.expiresAt <= 0
    ) {
      console.log(JSON.stringify({ status: "invalid_local_session" }));
      process.exitCode = 1;
      return;
    }
    let server: string;
    try {
      server = serverOrigin(stored.server);
    } catch {
      console.log(JSON.stringify({ status: "invalid_local_session" }));
      process.exitCode = 1;
      return;
    }
    const localStatus = stored.expiresAt <= Date.now() ? "expired" : "stored";
    let remoteVerification = "not_checked";
    let aliasVerification:
      | "not_checked"
      | "ready"
      | "requires_companion"
      | "not_found"
      | "unavailable" = "not_checked";
    if (args.includes("--remote") && localStatus === "stored") {
      try {
        const session = {
          server,
          accessToken: stored.accessToken,
          tenant: stored.tenant,
          expiresAt: stored.expiresAt,
          keys: await restoreSigningPair(privateKey(server)),
        };
        remoteVerification = await remoteAgentStatus(session);
        if (remoteVerification !== "authenticated") {
          process.exitCode = 1;
          if (requestedAlias) aliasVerification = "unavailable";
        } else if (requestedAlias) {
          aliasVerification = await remoteAliasStatus(
            session,
            requestedAlias.toUpperCase(),
          );
          if (aliasVerification !== "ready") process.exitCode = 1;
        }
      } catch {
        operation.signal.throwIfAborted();
        remoteVerification = "unavailable";
        if (requestedAlias) aliasVerification = "unavailable";
        process.exitCode = 1;
      }
    }
    if (requestedAlias && localStatus !== "stored") {
      aliasVerification = "unavailable";
      process.exitCode = 1;
    }
    console.log(
      JSON.stringify({
        status: localStatus,
        server,
        expiresAt: stored.expiresAt,
        remoteVerification,
        ...(requestedAlias
          ? {
              alias: requestedAlias.toUpperCase(),
              aliasVerification,
            }
          : {}),
      }),
    );
    return;
  }
  if (command === "logout") {
    if (!args.includes("--remote")) {
      clear();
      console.error(
        "Local session and signing key removed. The server-side grant remains active. Use agentsecret logout --remote while the local session is still available to revoke it before clearing local state.",
      );
      return;
    }
    let remoteRevocation = "not_attempted";
    let originalSession: ReturnType<typeof load> = null;
    let localSession = "unknown";
    try {
      const stored = load();
      originalSession = stored;
      if (stored) {
        localSession = "present";
        if (
          typeof stored.server !== "string" ||
          typeof stored.accessToken !== "string" ||
          !stored.accessToken ||
          typeof stored.tenant !== "string" ||
          !Number.isSafeInteger(stored.expiresAt) ||
          stored.expiresAt <= Date.now()
        ) {
          remoteRevocation = "unavailable";
        } else {
          const server = serverOrigin(stored.server);
          const keys = await restoreSigningPair(privateKey(server));
          const response = await fetch(server + "/api/agent/logout", {
            method: "POST",
            headers: {
              Authorization: "DPoP " + stored.accessToken,
              DPoP: await signProof(
                keys,
                "POST",
                server + "/api/agent/logout",
                stored.accessToken,
              ),
            },
            redirect: "error",
            signal: requestSignal(10000),
          });
          operation.signal.throwIfAborted();
          if (response.ok) {
            const result: unknown = await response.json();
            remoteRevocation =
              result &&
              typeof result === "object" &&
              !Array.isArray(result) &&
              Object.keys(result).join(",") === "success" &&
              (result as { success?: unknown }).success === true
                ? "revoked"
                : "unavailable";
          } else if (response.status === 401 || response.status === 403) {
            remoteRevocation = "rejected";
          } else {
            remoteRevocation = "unavailable";
          }
        }
      } else {
        localSession = "absent";
      }
    } catch {
      operation.signal.throwIfAborted();
      remoteRevocation = "unavailable";
    } finally {
      if (originalSession) {
        try {
          localSession = clearIfUnchanged(originalSession);
        } catch {
          localSession = "unknown";
        }
      }
    }
    const status =
      localSession === "replacement_preserved"
        ? "newer_session_preserved"
        : localSession === "unknown"
          ? "logout_incomplete"
          : "logged_out";
    console.log(
      JSON.stringify({
        status,
        remoteRevocation,
        localSession,
      }),
    );
    if (
      (remoteRevocation !== "revoked" &&
        remoteRevocation !== "not_attempted") ||
      localSession === "unknown"
    )
      process.exitCode = 1;
    return;
  }
  if (command === "browser" && args[0] === "identity") {
    args.shift();
    const store = new ExecutorStore(macOsExecutorBackend());
    let identity = await store.load();
    const created = !identity;
    if (!identity) {
      identity = await createExecutorIdentity();
      await store.save(identity);
    }
    console.log(
      JSON.stringify({
        status: "executor_identity",
        created,
        identity: publicExecutorIdentity(identity),
      }),
    );
    return;
  }
  if (command === "browser" && args[0] === "act") {
    args.shift();
    const failBrowser = (reason: string) => {
      console.log(JSON.stringify({ status: "browser_action_failed", reason }));
      process.exitCode = 1;
    };
    if (option("chrome") !== undefined) {
      failBrowser("browser_executable_override_denied");
      return;
    }
    const chromeBin = TRUSTED_CHROME_EXECUTABLE;
    const receiptDirectory =
      option("receipt-dir") || join(configDir, "browser-actions");
    try {
      verifyTrustedChromeInstallation(chromeBin);
      const session = await credentials();
      const executor = await new ExecutorStore(macOsExecutorBackend()).load();
      if (!executor) {
        failBrowser("trusted_executor_not_enrolled");
        return;
      }
      const receipt = await runBrowserAction(
        {
          grantId: option("grant") || "",
          kind: option("kind") || "",
          origin: option("origin") || "",
          fieldSelector: option("selector") || "",
          reference: option("reference") || "",
          url: option("url"),
        },
        {
          executor,
          accountId: session.tenant,
          server: session.server,
          fetchImpl: (url, init) =>
            fetch(url, {
              method: init.method,
              headers: init.headers,
              body: init.body,
              redirect: "error",
              signal: requestSignal(20000),
            }),
          signal: operation.signal,
          receipts: new BrowserActionReceiptStore(receiptDirectory),
          now: () => Date.now(),
          launchDriver: ({ url, origin }) =>
            launchChromeDriver({
              executable: chromeBin,
              url,
              origin,
              signal: operation.signal,
            }),
          resolveSecret: ({ alias, reference }) =>
            resolveBrowserSecret(session, alias, reference).catch(
              (error: unknown) => {
                throw new BrowserActionSetupError(
                  error instanceof Error
                    ? error
                    : new Error("browser_secret_unavailable"),
                );
              },
            ),
          storeCaptured: ({ alias, reference, value, authorizeDispatch }) =>
            storeBrowserCapture(
              session,
              alias,
              reference,
              value,
              authorizeDispatch,
            ).catch((error: unknown) => {
              const code = error instanceof Error ? error.message : "";
              if (
                code === "browser_capture_provider_unsupported" ||
                code === "browser_capture_write_denied"
              )
                throw new BrowserActionSetupError(
                  error instanceof Error
                    ? error
                    : new Error("browser_capture_store_failed"),
                );
              throw error;
            }),
        },
      );
      console.log(JSON.stringify(receipt));
    } catch (error) {
      if (operation.signal.aborted) throw error;
      if (error instanceof BrowserActionError) {
        failBrowser(error.code);
        return;
      }
      if (error instanceof Error && /^[a-z0-9_]{1,80}$/u.test(error.message)) {
        failBrowser(error.message);
        return;
      }
      throw error;
    }
    return;
  }
  if (command === "runtime" && args[0] === "qualify") {
    args.shift();
    const flag = (name: string): string | undefined => {
      const index = args.indexOf("--" + name);
      return index >= 0 ? args[index + 1] : undefined;
    };
    const sbxPath =
      flag("sbx") ?? process.env.AGENTSECRET_SBX ?? "/usr/local/bin/sbx";
    const evidencePath = flag("evidence");
    const fail = (reason: string) => {
      console.log(
        JSON.stringify({ status: "runtime_qualification_failed", reason }),
      );
      process.exitCode = 1;
    };
    if (!evidencePath) {
      fail("evidence_path_required");
      return;
    }
    let evidenceSha256: string;
    try {
      evidenceSha256 = createHash("sha256")
        .update(readFileSync(evidencePath))
        .digest("hex");
    } catch {
      fail("evidence_unreadable");
      return;
    }
    if (evidenceSha256 !== T015_EVIDENCE_SHA256) {
      fail("evidence_digest_mismatch");
      return;
    }
    let sbxSha256: string;
    let sbxVersion: string;
    try {
      sbxSha256 = createHash("sha256")
        .update(readFileSync(sbxPath))
        .digest("hex");
      if (sbxSha256 !== SBX_QUALIFIED_SHA256) {
        fail("sbx_artifact_mismatch");
        return;
      }
      const versionOutput = execFileSync(sbxPath, ["--version"], {
        encoding: "utf8",
      });
      const versionMatch = versionOutput.match(
        new RegExp("v[0-9]+[.][0-9]+[.][0-9]+"),
      );
      sbxVersion = versionMatch?.[0] ?? "";
    } catch {
      fail("sbx_artifact_unreadable");
      return;
    }
    if (
      sbxVersion !== SBX_QUALIFIED_VERSION ||
      sbxSha256 !== SBX_QUALIFIED_SHA256
    ) {
      fail("sbx_artifact_mismatch");
      return;
    }
    writeRuntimeQualificationReceipt(configDir);
    console.log(
      JSON.stringify({
        status: "runtime_qualified",
        sbx_version: SBX_QUALIFIED_VERSION,
        sbx_sha256: SBX_QUALIFIED_SHA256,
        evidence_sha256: T015_EVIDENCE_SHA256,
      }),
    );
    return;
  }
  if (command === "run") {
    if (!runtimeQualified(configDir)) {
      console.log(
        JSON.stringify({
          status: "runtime_not_qualified",
          reason: "macos_runtime_and_strict_credential_mediation_required",
        }),
      );
      process.exitCode = 1;
      return;
    }
    if (args[0] === "browser") {
      let managed;
      try {
        if (option("chrome") !== undefined)
          throw new Error("browser_executable_override_denied");
        managed = parseManagedBrowserArgs(args);
      } catch {
        console.log(
          JSON.stringify({
            schema: "agentsecret.run/browser/v1",
            status: "failed",
            reason: "invalid_browser_action_request",
          }),
        );
        process.exitCode = 1;
        return;
      }
      const receiptDirectory = managedBrowserReceiptDirectory(
        configDir,
        option("receipt-dir"),
      );
      try {
        verifyTrustedChromeInstallation(TRUSTED_CHROME_EXECUTABLE);
        const browserSession = await credentials();
        const browserExecutor = await new ExecutorStore(
          macOsExecutorBackend(),
        ).load();
        if (!browserExecutor) {
          console.log(
            JSON.stringify({
              schema: "agentsecret.run/browser/v1",
              status: "failed",
              reason: "trusted_executor_not_enrolled",
            }),
          );
          process.exitCode = 1;
          return;
        }
        const receipt = await runManagedBrowserAction(managed, {
          executor: browserExecutor,
          accountId: browserSession.tenant,
          server: browserSession.server,
          fetchImpl: (url, init) =>
            fetch(url, {
              method: init.method,
              headers: init.headers,
              body: init.body,
              redirect: "error",
              signal: requestSignal(20000),
            }),
          signal: operation.signal,
          receiptDirectory,
          now: () => Date.now(),
          launchDriver: ({ url, origin }) =>
            launchChromeDriver({
              executable: TRUSTED_CHROME_EXECUTABLE,
              url,
              origin,
              signal: operation.signal,
            }),
          resolveSecret: ({ alias, reference }) =>
            resolveBrowserSecret(browserSession, alias, reference).catch(
              (error: unknown) => {
                throw new BrowserActionSetupError(
                  error instanceof Error
                    ? error
                    : new Error("browser_secret_unavailable"),
                );
              },
            ),
          storeCaptured: ({ alias, reference, value, authorizeDispatch }) =>
            storeBrowserCapture(
              browserSession,
              alias,
              reference,
              value,
              authorizeDispatch,
            ).catch((error: unknown) => {
              const code = error instanceof Error ? error.message : "";
              if (
                code === "browser_capture_provider_unsupported" ||
                code === "browser_capture_write_denied"
              )
                throw new BrowserActionSetupError(
                  error instanceof Error
                    ? error
                    : new Error("browser_capture_store_failed"),
                );
              throw error;
            }),
        });
        console.log(JSON.stringify(receipt));
        process.exitCode = receipt.status === "completed" ? 0 : 1;
      } catch (error) {
        if (operation.signal.aborted) throw error;
        console.log(
          JSON.stringify({
            schema: "agentsecret.run/browser/v1",
            status: "failed",
            reason:
              error instanceof Error && /^[a-z0-9_]{1,80}$/u.test(error.message)
                ? error.message
                : "browser_action_failed",
          }),
        );
        process.exitCode = 1;
      }
      return;
    }
    let hostRoot: string;
    try {
      hostRoot = realpathSync(process.cwd());
    } catch {
      console.log(
        JSON.stringify({
          status: "invalid_run_request",
          reason: "host_root_invalid",
        }),
      );
      process.exitCode = 1;
      return;
    }
    let spec: RunSpec;
    try {
      spec = parseRunArgs(args, hostRoot);
    } catch (error) {
      const reason =
        error instanceof RunSpecError ? error.code : "run_spec_invalid";
      console.log(JSON.stringify({ status: "invalid_run_request", reason }));
      process.exitCode = 1;
      return;
    }
    const receipt = await runGuestCommand(spec, {
      hostRoot,
      configDir,
      signal: operation.signal,
      stdout: process.stdout,
      stderr: process.stderr,
    });
    console.log(JSON.stringify(receipt));
    process.exitCode =
      receipt.status === "completed"
        ? 0
        : receipt.status === "cancelled"
          ? 130
          : 1;
    return;
  }
  if (
    command === "secrets" &&
    ["save", "update", "delete"].includes(args[0] || "")
  ) {
    const action = args.shift() as "save" | "update" | "delete";
    const alias = option("alias");
    const targetOption = action === "save" ? "--title" : "--reference";
    const target = option(targetOption.slice(2));
    const serverValue = option("server");
    const rawServerAuthority =
      typeof serverValue === "string"
        ? /^https?:\/\/([^/\\?#]+)/i.exec(serverValue)?.[1]
        : undefined;
    const usage =
      action === "save"
        ? "Use secrets save --alias <alias> --title <title>."
        : action === "delete"
          ? "Use secrets delete --alias <alias> --reference <ref>."
          : "Use secrets update --alias <alias> --reference <ref>.";
    if (
      ["--alias", targetOption, "--server", "--new-operation"].some(
        (flag) => args.filter((arg) => arg === flag).length > 1,
      )
    )
      throw new Error(`Use each secrets ${action} option at most once.`);
    if (args.includes("--value"))
      throw new Error(
        "Secret values must be entered at the hidden terminal prompt; command-line arguments are refused.",
      );
    const replacePending = args.includes("--new-operation");
    const hasServerOption = args.includes("--server");
    const normalizedTarget = action === "save" ? target?.trim() : target;
    const validServer = (() => {
      if (!hasServerOption) return true;
      if (
        typeof serverValue !== "string" ||
        !serverValue ||
        serverValue !== serverValue.trim() ||
        !rawServerAuthority ||
        rawServerAuthority.includes("@") ||
        !isWellFormedUnicode(serverValue) ||
        /[\u0000-\u001f\u007f-\u009f]/.test(serverValue) ||
        !/^https?:\/\/[^/\\?#]+\/?$/i.test(serverValue)
      )
        return false;
      try {
        serverOrigin(serverValue);
        return true;
      } catch {
        return false;
      }
    })();
    const validRawTarget =
      typeof target === "string" &&
      isWellFormedUnicode(target) &&
      !/[\u0000-\u001f\u007f-\u009f]/.test(target) &&
      !target.includes("\ufffd");
    const validTarget =
      typeof normalizedTarget === "string" &&
      normalizedTarget.length > 0 &&
      isWellFormedUnicode(normalizedTarget) &&
      !/[\u0000-\u001f\u007f-\u009f]/.test(normalizedTarget) &&
      !normalizedTarget.includes("\ufffd") &&
      !normalizedTarget.startsWith("-") &&
      (action === "save"
        ? target === normalizedTarget && target.length <= 128
        : normalizedTarget === normalizedTarget.trim() &&
          normalizedTarget.length <= 1024 &&
          (parseConnectReference(normalizedTarget) !== null ||
            (() => {
              try {
                parseOnePasswordServiceAccountReference(normalizedTarget);
                return true;
              } catch {
                return false;
              }
            })()));
    if (
      !alias ||
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias) ||
      !validRawTarget ||
      !validTarget ||
      !validServer ||
      typeof target !== "string" ||
      target.startsWith("--") ||
      args.length !==
        4 + (hasServerOption ? 2 : 0) + (replacePending ? 1 : 0) ||
      args.filter((arg) => arg === "--alias").length !== 1 ||
      args.filter((arg) => arg === targetOption).length !== 1 ||
      args.filter((arg) => arg === "--server").length !==
        (hasServerOption ? 1 : 0) ||
      args.filter((arg) => arg === "--new-operation").length !==
        (replacePending ? 1 : 0) ||
      args.some(
        (arg) =>
          ![
            "--alias",
            targetOption,
            "--server",
            "--new-operation",
            alias,
            target,
            serverValue,
          ].includes(arg),
      )
    )
      throw new Error(usage);
    requireInteractiveSecretTerminal();
    const session = await credentials();
    const route =
      action === "save"
        ? "/api/agent/secrets/save"
        : action === "delete"
          ? "/api/agent/secrets/delete"
          : "/api/agent/secrets/update";
    const normalizedAlias = alias.toUpperCase();
    const value = action === "delete" ? undefined : await readSecretInput();
    if (action === "delete") await confirmExactSecretDeletion(normalizedTarget);
    const operationKey = await hash(
      JSON.stringify([
        session.server,
        session.tenant,
        normalizedAlias,
        action,
        normalizedTarget,
      ]),
    );
    if (replacePending)
      console.error(
        "Starting a new operation may duplicate an unresolved provider write; use this only after checking the vault.",
      );
    const operationId = await beginPendingSecretWrite(
      operationKey,
      random(32),
      replacePending,
    );
    if (action !== "delete") {
      const serviceAccountBinding = await serviceAccountBindingForAlias(
        session,
        normalizedAlias,
        action === "save" ? "create" : "update",
      );
      if (serviceAccountBinding) {
        const receipt = await fulfillServiceAccountWrite(
          session,
          serviceAccountBinding,
          normalizedAlias,
          action,
          normalizedTarget,
          operationId,
          value as string,
        );
        await completePendingSecretWrite(operationKey, operationId);
        console.log(
          JSON.stringify({
            status: receipt.status,
            reference: receipt.reference,
            verified: true,
          }),
        );
        return;
      }
    } else {
      const serviceAccountBinding = await serviceAccountBindingForAlias(
        session,
        normalizedAlias,
        "delete",
      );
      if (serviceAccountBinding) {
        const receipt = await fulfillServiceAccountDelete(
          session,
          serviceAccountBinding,
          normalizedAlias,
          normalizedTarget,
          operationId,
        );
        await completePendingSecretWrite(operationKey, operationId);
        console.log(
          JSON.stringify({
            status: receipt.status,
            reference: receipt.reference,
            verified: true,
          }),
        );
        return;
      }
    }
    let response: Response;
    try {
      response = await broker(
        route,
        {
          alias: normalizedAlias,
          operationId,
          ...(action === "save"
            ? { title: normalizedTarget }
            : { reference: normalizedTarget }),
          ...(value === undefined ? {} : { value }),
        },
        session,
      );
    } catch {
      throw new Error(
        action === "delete"
          ? "Delete outcome may be unknown. The operation ID was saved; rerun the same command with the same alias and reference to check its receipt."
          : "Write outcome may be unknown. The operation ID was saved; rerun the same command with the same target and value to check its receipt.",
      );
    }
    if (!response.ok) {
      let errorCode = "";
      try {
        const error = await response.json();
        if (
          typeof error?.error === "string" &&
          /^[a-z0-9_]{1,80}$/.test(error.error)
        )
          errorCode = error.error;
      } catch {
        // Never include a provider or proxy response body in CLI output.
      }
      if (errorCode === "save_outcome_unknown")
        throw new Error(
          action === "delete"
            ? "Delete outcome is unknown. The operation ID was saved; rerun the same command with the same alias and reference to check its receipt. Do not use --new-operation until you have checked the vault."
            : "Write outcome is unknown. The operation ID was saved; rerun the same command with the same target and value to check its receipt. Do not use --new-operation until you have checked the vault.",
        );
      if (errorCode === "secret_save_operation_conflict")
        throw new Error(
          "This operation ID is bound to another input. Check the vault before using --new-operation.",
        );
      throw new Error(
        `Secret ${action} failed (${errorCode || response.status}); the operation ID is retained for retry.`,
      );
    }
    let result: any;
    try {
      result = await response.json();
    } catch {
      throw new Error("Broker returned an invalid secret write response.");
    }
    if (
      !["created", "updated", "deleted"].includes(result.status) ||
      result.verified !== true ||
      typeof result.reference !== "string"
    )
      throw new Error("Broker returned an unverified secret write response.");
    await completePendingSecretWrite(operationKey, operationId);
    console.log(
      JSON.stringify({
        status: result.status,
        reference: result.reference,
        verified: true,
      }),
    );
    return;
  }
  if (command === "secrets" && args[0] === "ensure") {
    args.shift();
    const alias = option("alias");
    const reference = option("reference");
    if (args.includes("--value"))
      throw new Error(
        "Ensure values are entered only in the authenticated owner dashboard; command-line values are refused.",
      );
    const replacePending = args.includes("--new-operation");
    if (
      !alias ||
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias) ||
      !reference?.trim() ||
      reference !== reference.trim() ||
      reference.length > 1024 ||
      /[\u0000-\u001f\u007f]/.test(reference) ||
      hasUnsafeConnectReferenceText(reference) ||
      args.length !== (replacePending ? 5 : 4) ||
      args.filter((arg) => arg === "--alias").length !== 1 ||
      args.filter((arg) => arg === "--reference").length !== 1 ||
      args.some(
        (arg) =>
          ![
            "--alias",
            "--reference",
            "--new-operation",
            alias,
            reference,
          ].includes(arg),
      )
    )
      throw new Error("Use secrets ensure --alias <alias> --reference <ref>.");

    const session = await credentials();
    const normalizedAlias = alias.toUpperCase();
    const operationKey = await hash(
      JSON.stringify([
        session.server,
        session.tenant,
        normalizedAlias,
        "ensure",
        reference,
      ]),
    );
    if (replacePending)
      console.error(
        "Starting a new ensure request may duplicate owner input; use this only after checking the dashboard.",
      );
    const operationId = await beginPendingSecretWrite(
      operationKey,
      random(32),
      replacePending,
    );
    const serviceAccountBinding = await serviceAccountBindingForAlias(
      session,
      normalizedAlias,
      "update",
    );
    if (serviceAccountBinding) {
      requireInteractiveSecretTerminal();
      const expectedValue = await readSecretInput();
      const receipt = await fulfillServiceAccountWrite(
        session,
        serviceAccountBinding,
        normalizedAlias,
        "ensure",
        reference,
        operationId,
        expectedValue,
      );
      await completePendingSecretWrite(operationKey, operationId);
      console.log(
        JSON.stringify({
          status: receipt.status,
          reference: receipt.reference,
          verified: true,
        }),
      );
      return;
    }
    let response: Response;
    try {
      response = await broker("/mcp", {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "secrets_save",
          arguments: {
            secret_alias: normalizedAlias,
            operation_id: operationId,
            intent: "ensure",
            reference,
          },
        },
      });
    } catch {
      throw new Error(
        "Ensure request outcome may be unknown. The operation ID is saved; rerun with the same alias and reference to check it.",
      );
    }
    if (!response.ok)
      throw new Error("Secret ensure was denied by the broker.");

    let envelope: {
      jsonrpc?: unknown;
      id?: unknown;
      result?: {
        isError?: unknown;
        content?: Array<{ type?: unknown; text?: unknown }>;
      };
      error?: unknown;
    };
    try {
      envelope = (await response.json()) as typeof envelope;
    } catch {
      throw new Error("Broker returned an invalid secret ensure response.");
    }
    if (
      !envelope ||
      typeof envelope !== "object" ||
      Array.isArray(envelope) ||
      envelope.jsonrpc !== "2.0" ||
      envelope.id !== 1 ||
      Object.hasOwn(envelope, "error")
    )
      throw new Error("Broker returned an invalid secret ensure response.");
    const content = envelope.result?.content;
    const text =
      Array.isArray(content) &&
      content.length === 1 &&
      content[0]?.type === "text" &&
      typeof content[0].text === "string"
        ? content[0].text
        : undefined;
    if (
      !text ||
      (envelope.result?.isError !== undefined &&
        typeof envelope.result.isError !== "boolean") ||
      envelope.result?.isError === true
    )
      throw new Error("Secret ensure was denied by the broker.");
    let result: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
        throw new Error();
      result = parsed as Record<string, unknown>;
    } catch {
      throw new Error("Broker returned an invalid secret ensure result.");
    }

    if (
      ["owner_input_required", "outcome_unknown"].includes(
        String(result.status),
      )
    ) {
      if (
        Object.keys(result).sort().join(",") !== "requestId,status" ||
        typeof result.requestId !== "string" ||
        !/^[A-Za-z0-9_-]{20,128}$/.test(result.requestId)
      )
        throw new Error("Broker returned an invalid secret ensure result.");
      console.log(
        JSON.stringify({
          status: result.status,
          requestId: result.requestId,
        }),
      );
      if (result.status === "outcome_unknown") process.exitCode = 1;
      return;
    }

    if (["unchanged", "updated"].includes(String(result.status))) {
      if (
        !["reference", "replayed", "status", "verified"].every((key) =>
          Object.hasOwn(result, key),
        ) ||
        Object.keys(result).some(
          (key) =>
            ![
              "status",
              "reference",
              "verified",
              "replayed",
              "requestId",
            ].includes(key),
        ) ||
        (result.requestId !== undefined &&
          (typeof result.requestId !== "string" ||
            !/^[A-Za-z0-9_-]{43}$/.test(result.requestId))) ||
        result.reference !== reference ||
        result.verified !== true ||
        typeof result.replayed !== "boolean"
      )
        throw new Error("Broker returned an invalid secret ensure receipt.");
      await completePendingSecretWrite(operationKey, operationId);
      console.log(
        JSON.stringify({
          status: result.status,
          reference,
          verified: true,
        }),
      );
      return;
    }

    if (
      ["rejected", "expired"].includes(String(result.status)) &&
      Object.keys(result).sort().join(",") === "status"
    ) {
      await completePendingSecretWrite(operationKey, operationId);
      console.log(JSON.stringify({ status: result.status }));
      process.exitCode = 1;
      return;
    }
    throw new Error("Broker returned an invalid secret ensure result.");
  }
  if (command === "secrets" && args[0] === "fulfill") {
    args.shift();
    const requestId = option("request-id");
    if (
      !requestId ||
      !/^[A-Za-z0-9_-]{43}$/.test(requestId) ||
      args.length !== 2 ||
      args.join("\u0000") !== "--request-id\u0000" + requestId
    )
      throw new Error("Use secrets fulfill --request-id <id>.");
    const session = await credentials();
    const receipt = await fulfillExistingServiceAccountRequest(
      session,
      requestId,
    );
    console.log(
      JSON.stringify({
        status: receipt.status,
        reference: receipt.reference,
        verified: true,
      }),
    );
    return;
  }
  if (command === "secrets" && args[0] === "list") {
    args.shift();
    const response = await broker("/mcp", {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "list_available_secrets", arguments: {} },
    });
    if (!response.ok)
      throw new Error("Secret alias discovery was denied by the broker.");
    let envelope: {
      result?: { isError?: boolean; content?: Array<{ text?: string }> };
      error?: unknown;
    };
    try {
      envelope = (await response.json()) as typeof envelope;
    } catch {
      throw new Error("Broker returned an invalid secret alias response.");
    }
    const text = envelope.result?.content?.[0]?.text;
    if (envelope.error || envelope.result?.isError || !text)
      throw new Error("Secret alias discovery was denied by the broker.");
    let result: unknown;
    try {
      result = JSON.parse(text);
    } catch {
      throw new Error("Broker returned an invalid secret alias response.");
    }
    const available = (result as { available_secrets?: unknown } | null)
      ?.available_secrets;
    if (!Array.isArray(available))
      throw new Error("Broker returned an invalid secret alias response.");
    const aliases = available.map((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry))
        throw new Error("Broker returned an invalid secret alias response.");
      const alias = (entry as { alias?: unknown }).alias;
      const allowedDomains = (entry as { allowedDomains?: unknown })
        .allowedDomains;
      const allowedMethods = (entry as { allowedMethods?: unknown })
        .allowedMethods;
      const connectionStatus = (entry as { connection_status?: unknown })
        .connection_status;
      const providerMode = (entry as { provider_mode?: unknown }).provider_mode;
      const providerCapabilities = (
        entry as { provider_capabilities?: unknown }
      ).provider_capabilities;
      const companionBinding = (entry as { companion_binding?: unknown })
        .companion_binding;
      const credentialSink = (entry as { credential_sink?: unknown })
        .credential_sink;
      const validCredentialSink = (() => {
        if (credentialSink === undefined) return true;
        if (
          !credentialSink ||
          typeof credentialSink !== "object" ||
          Array.isArray(credentialSink)
        )
          return false;
        const sink = credentialSink as Record<string, unknown>;
        if (sink.type === "bearer" || sink.type === "basic")
          return Object.keys(sink).join(",") === "type";
        if (sink.type === "header")
          return (
            Object.keys(sink).sort().join(",") === "name,type" &&
            typeof sink.name === "string" &&
            /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(sink.name)
          );
        if (sink.type === "query_param")
          return (
            Object.keys(sink).sort().join(",") === "name,type" &&
            typeof sink.name === "string" &&
            /^[A-Za-z0-9_-]{1,80}$/.test(sink.name)
          );
        if (sink.type === "body_placeholder")
          return (
            Object.keys(sink).sort().join(",") === "marker,type" &&
            sink.marker === SECRET_BODY_PLACEHOLDER
          );
        return false;
      })();
      const capabilityObject =
        providerCapabilities &&
        typeof providerCapabilities === "object" &&
        !Array.isArray(providerCapabilities)
          ? (providerCapabilities as Record<string, unknown>)
          : undefined;
      const companionProviderModes = [
        "bitwarden-password-manager",
        "onepassword-service-account",
        "lastpass",
      ];
      const validCompanionBinding = (() => {
        if (
          !companionBinding ||
          typeof companionBinding !== "object" ||
          Array.isArray(companionBinding)
        )
          return false;
        const binding = companionBinding as Record<string, unknown>;
        return (
          Object.keys(binding).sort().join(",") ===
            "connection_id,connection_revision" &&
          typeof binding.connection_id === "string" &&
          /^[A-Za-z0-9_-]{16,128}$/.test(binding.connection_id) &&
          Number.isSafeInteger(binding.connection_revision) &&
          (binding.connection_revision as number) >= 1
        );
      })();
      const validConnectionCapabilities =
        connectionStatus === "ready"
          ? [
              "bitwarden-secrets-manager",
              "bitwarden-password-manager",
              "onepassword-connect",
              "onepassword-service-account",
              "lastpass",
            ].includes(providerMode as string) &&
            !!capabilityObject &&
            [
              "conditional_update,create,delete,read,status,update,verify_after_write",
              "conditional_update,create,delete,read,reason,status,update,verify_after_write",
            ].includes(Object.keys(capabilityObject).sort().join(",")) &&
            [
              "read",
              "create",
              "update",
              "conditional_update",
              "verify_after_write",
              "delete",
            ].every((key) => typeof capabilityObject[key] === "boolean") &&
            (capabilityObject.reason === undefined ||
              (typeof capabilityObject.reason === "string" &&
                capabilityObject.reason.trim().length > 0 &&
                capabilityObject.reason.length <= 512 &&
                !/[\u0000-\u001f\u007f]/.test(capabilityObject.reason))) &&
            (companionProviderModes.includes(providerMode as string)
              ? capabilityObject.status === "requires-companion" &&
                validCompanionBinding
              : ["implemented", "unsupported"].includes(
                  capabilityObject.status as string,
                ) && companionBinding === undefined)
          : ["unavailable", "unbound"].includes(connectionStatus as string) &&
            providerMode === undefined &&
            providerCapabilities === undefined &&
            companionBinding === undefined;
      const ownerWriteGrant = (entry as { owner_write_grant?: unknown })
        .owner_write_grant;
      const validWriteGrant =
        ownerWriteGrant === undefined ||
        (!!ownerWriteGrant &&
          typeof ownerWriteGrant === "object" &&
          !Array.isArray(ownerWriteGrant) &&
          Object.keys(ownerWriteGrant).every((key) =>
            ["create", "update", "delete"].includes(key),
          ) &&
          ["create", "update", "delete"].every(
            (key) =>
              typeof (ownerWriteGrant as Record<string, unknown>)[key] ===
              "boolean",
          ));
      if (
        typeof alias !== "string" ||
        !/^[A-Z][A-Z0-9_]{0,63}$/.test(alias) ||
        !Array.isArray(allowedDomains) ||
        allowedDomains.length < 1 ||
        allowedDomains.length > 20 ||
        !allowedDomains.every(
          (domain) =>
            typeof domain === "string" &&
            domain.length <= 253 &&
            /^(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z0-9-]+$/i.test(domain),
        ) ||
        !Array.isArray(allowedMethods) ||
        allowedMethods.length < 1 ||
        !allowedMethods.every(
          (method) =>
            typeof method === "string" &&
            [
              "GET",
              "POST",
              "PUT",
              "PATCH",
              "DELETE",
              "HEAD",
              "OPTIONS",
            ].includes(method),
        ) ||
        !validWriteGrant ||
        !validCredentialSink ||
        !validConnectionCapabilities
      )
        throw new Error("Broker returned an invalid secret alias response.");
      return {
        alias,
        allowedDomains,
        allowedMethods,
        ...(credentialSink === undefined
          ? {}
          : { credential_sink: credentialSink }),
        connection_status: connectionStatus,
        ...(providerMode === undefined
          ? {}
          : {
              provider_mode: providerMode,
              provider_capabilities: providerCapabilities,
              ...(validCompanionBinding
                ? { companion_binding: companionBinding }
                : {}),
            }),
        ...(ownerWriteGrant === undefined
          ? {}
          : { owner_write_grant: ownerWriteGrant }),
      };
    });
    console.log(JSON.stringify({ available_secrets: aliases }));
    return;
  }
  if (command === "secrets" && args.shift() === "find") {
    const alias = option("alias");
    if (!alias || !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(alias))
      throw new Error("Use secrets find with a valid --alias.");
    const reference = option("reference");
    const store = option("store");
    const bindingText = option("binding");
    const inputsText = option("inputs");
    const title = option("title");
    const loginLocatorText = option("login-lookup");
    const findOptions = [
      "--alias",
      "--reference",
      "--store",
      "--binding",
      "--inputs",
      "--title",
      "--login-lookup",
      "--optional",
    ];
    if (
      findOptions.some((flag) => args.filter((arg) => arg === flag).length > 1)
    )
      throw new Error("Use each secrets find option at most once.");
    const stores = [
      "bitwarden-cli",
      "bitwarden-secrets-manager",
      "onepassword-connect",
      "onepassword-service-account",
      "lastpass",
    ];
    let binding: Record<string, unknown> | undefined;
    let inputRef: Record<string, unknown> | undefined;
    let inputLocator: Record<string, unknown> | undefined;
    let normalizedBindingStore: string | undefined;
    let namedSecretTitle: string | undefined;
    let loginLookupBinding = false;
    if (bindingText !== undefined) {
      try {
        if (bindingText.length > 4096) throw new Error();
        const parsed = JSON.parse(bindingText);
        const parsedInputs =
          inputsText === undefined
            ? undefined
            : inputsText.length <= 4096
              ? JSON.parse(inputsText)
              : null;
        const direct = normalizeSecretRefBinding(parsed);
        const fromInput = normalizeSecretRefInputBinding(parsed, parsedInputs);
        const namedSecret = normalizeNamedSecretLocatorBinding(parsed);
        const namedSecretInput = normalizeNamedSecretLocatorInputBinding(
          parsed,
          parsedInputs,
        );
        const loginLookup = normalizeLoginLookupLocatorBinding(parsed);
        const loginLookupInput = normalizeLoginLookupLocatorInputBinding(
          parsed,
          parsedInputs,
        );
        const envVar = normalizeEnvVarLocatorBinding(parsed);
        const envVarInput = normalizeEnvVarLocatorInputBinding(
          parsed,
          parsedInputs,
        );
        if (envVar || envVarInput) throw new Error("local_only_env_var");
        {
          const directOrInputRef = direct ?? fromInput;
          if (
            directOrInputRef &&
            COMPANION_ONLY_STORES.has(directOrInputRef.store)
          )
            throw new Error("secret_store_unavailable");
          const resolved =
            namedSecret ?? namedSecretInput ?? loginLookup ?? loginLookupInput;
          if (resolved && COMPANION_ONLY_STORES.has(resolved.store))
            throw new Error("secret_store_unavailable");
          if (resolved && LOCATOR_UNSUPPORTED_STORES.has(resolved.store))
            throw new Error("secret_binding_unsupported");
        }
        const resolvedNamedSecret = namedSecret ?? namedSecretInput;
        const resolvedLoginLookup = loginLookup ?? loginLookupInput;
        const normalized = direct ?? fromInput;
        if (
          (!normalized && !resolvedNamedSecret && !resolvedLoginLookup) ||
          (normalized &&
            ((normalized.store === "bitwarden-secrets-manager" &&
              normalized.fieldPath !== null &&
              normalized.fieldPath !== "") ||
              (normalized.store !== "bitwarden-secrets-manager" &&
                normalized.store !== "onepassword-connect") ||
              (normalized.store === "onepassword-connect" &&
                !normalized.reference))) ||
          (resolvedNamedSecret &&
            (resolvedNamedSecret.store !== "onepassword-connect" ||
              (resolvedNamedSecret.fieldPath !== null &&
                resolvedNamedSecret.fieldPath !== "") ||
              (namedSecret !== null &&
                namedSecret !== undefined &&
                inputsText !== undefined) ||
              (namedSecretInput !== null &&
                namedSecretInput !== undefined &&
                inputsText === undefined))) ||
          (resolvedLoginLookup &&
            (resolvedLoginLookup.store !== "onepassword-connect" ||
              (resolvedLoginLookup.fieldPath !== null &&
                resolvedLoginLookup.fieldPath !== "") ||
              (loginLookup !== null &&
                loginLookup !== undefined &&
                inputsText !== undefined) ||
              (loginLookupInput !== null &&
                loginLookupInput !== undefined &&
                inputsText === undefined))) ||
          (direct !== null &&
            direct !== undefined &&
            inputsText !== undefined) ||
          (fromInput !== null &&
            fromInput !== undefined &&
            inputsText === undefined)
        )
          throw new Error();
        binding = parsed as Record<string, unknown>;
        normalizedBindingStore =
          normalized?.store ??
          resolvedNamedSecret?.store ??
          resolvedLoginLookup?.store;
        namedSecretTitle = resolvedNamedSecret?.name;
        loginLookupBinding =
          resolvedLoginLookup !== null && resolvedLoginLookup !== undefined;
        if (fromInput) {
          const rawInput = (parsed as Record<string, unknown>).secret_ref_input;
          const inputName =
            typeof rawInput === "string"
              ? rawInput.trim()
              : ((rawInput as Record<string, unknown>).name as string).trim();
          inputRef = (parsedInputs as Record<string, unknown>)[
            inputName
          ] as Record<string, unknown>;
        }
        if (namedSecretInput) {
          const rawInput = (parsed as Record<string, unknown>)
            .secret_locator_input;
          const inputName =
            typeof rawInput === "string"
              ? rawInput.trim()
              : ((rawInput as Record<string, unknown>).name as string);
          inputLocator = (parsedInputs as Record<string, unknown>)[
            inputName
          ] as Record<string, unknown>;
        }
        if (loginLookupInput) {
          const rawInput = (parsed as Record<string, unknown>)
            .secret_locator_input;
          const inputName =
            typeof rawInput === "string"
              ? rawInput.trim()
              : ((rawInput as Record<string, unknown>).name as string).trim();
          inputLocator = (parsedInputs as Record<string, unknown>)[
            inputName
          ] as Record<string, unknown>;
        }
      } catch (error) {
        if (
          error instanceof Error &&
          (error.message === "local_only_env_var" ||
            error.message === "secret_store_unavailable" ||
            error.message === "secret_binding_unsupported")
        )
          throw error;
        throw new Error(
          "Use --binding with a direct BWS UUID secret_ref, a direct Connect object/field secret_ref, or secret_ref_input plus --inputs containing only that ref; named_secret and login_lookup support direct owner-pinned Connect locators or secret_locator_input plus --inputs containing only that locator.",
        );
      }
    } else if (inputsText !== undefined) {
      throw new Error(
        "Use --inputs only with a secret_ref_input or secret_locator_input --binding.",
      );
    }
    let loginLocator: Record<string, unknown> | undefined;
    if (loginLocatorText !== undefined) {
      try {
        const parsed = JSON.parse(loginLocatorText);
        if (
          !parsed ||
          typeof parsed !== "object" ||
          Array.isArray(parsed) ||
          parsed.kind !== "login_lookup" ||
          typeof parsed.title !== "string" ||
          !parsed.title.trim() ||
          parsed.title.length > 128 ||
          /[\u0000-\u001f\u007f]/.test(parsed.title) ||
          hasUnsafeConnectReferenceCharacter(parsed.title) ||
          typeof parsed.username !== "string" ||
          !parsed.username.trim() ||
          parsed.username.length > 512 ||
          /[\u0000-\u001f\u007f]/.test(parsed.username) ||
          hasUnsafeConnectReferenceCharacter(parsed.username) ||
          !Array.isArray(parsed.uris) ||
          parsed.uris.length < 1 ||
          parsed.uris.length > 16 ||
          parsed.uris.some(
            (uri: unknown) =>
              typeof uri !== "string" ||
              !uri.trim() ||
              uri.length > 2048 ||
              /[\u0000-\u001f\u007f]/.test(uri) ||
              hasUnsafeConnectReferenceCharacter(uri),
          ) ||
          new Set(parsed.uris).size !== parsed.uris.length ||
          typeof parsed.fieldId !== "string" ||
          !parsed.fieldId.trim() ||
          parsed.fieldId.length > 256 ||
          /[\u0000-\u001f\u007f]/.test(parsed.fieldId) ||
          (parsed.fieldPath !== undefined &&
            (typeof parsed.fieldPath !== "string" ||
              !parsed.fieldPath.trim() ||
              parsed.fieldPath.length > 256 ||
              /[\u0000-\u001f\u007f]/.test(parsed.fieldPath))) ||
          Object.keys(parsed).some(
            (key) =>
              ![
                "kind",
                "title",
                "username",
                "uris",
                "fieldId",
                "fieldPath",
              ].includes(key),
          )
        )
          throw new Error();
        loginLocator = parsed as Record<string, unknown>;
      } catch {
        throw new Error(
          "Use --login-lookup with a valid JSON login locator containing kind, title, username, unique uris, and fieldId; fieldPath is optional.",
        );
      }
    }
    if (
      (args.includes("--reference") &&
        (reference === undefined || reference.startsWith("--"))) ||
      (reference !== undefined &&
        (!reference.trim() ||
          reference !== reference.trim() ||
          reference.length > 1024 ||
          /[\u0000-\u001f\u007f]/.test(reference) ||
          hasUnsafeConnectReferenceText(reference))) ||
      (args.includes("--store") &&
        (store === undefined || !stores.includes(store))) ||
      (store !== undefined && !stores.includes(store)) ||
      (args.includes("--binding") &&
        (bindingText === undefined || bindingText.startsWith("--"))) ||
      (args.includes("--inputs") &&
        (inputsText === undefined || inputsText.startsWith("--"))) ||
      (args.includes("--title") &&
        (title === undefined || title.startsWith("--"))) ||
      (args.includes("--login-lookup") &&
        (loginLocatorText === undefined ||
          loginLocatorText.startsWith("--"))) ||
      (title !== undefined &&
        (!title.trim() ||
          title.length > 128 ||
          /[\u0000-\u001f\u007f]/.test(title) ||
          hasUnsafeConnectReferenceCharacter(title))) ||
      (reference !== undefined &&
        (title !== undefined || loginLocator || binding)) ||
      (title !== undefined && loginLocator) ||
      (binding !== undefined &&
        (title !== undefined ||
          loginLocator !== undefined ||
          (store !== undefined && store !== normalizedBindingStore)))
    )
      throw new Error(
        "Use secrets find with one compatible selector: --reference, --binding, --title, or --login-lookup.",
      );
    const session = await credentials();
    const response = await broker(
      "/mcp",
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "secrets_find",
          arguments: {
            secret_alias: alias,
            ...(store === undefined ? {} : { store }),
            ...(reference === undefined ? {} : { reference }),
            ...(binding === undefined ? {} : { binding }),
            ...(inputRef === undefined ? {} : { input_ref: inputRef }),
            ...(inputLocator === undefined
              ? {}
              : { input_locator: inputLocator }),
            ...(namedSecretTitle !== undefined ||
            loginLookupBinding ||
            (title === undefined && !loginLocator)
              ? {}
              : {
                  selector: loginLocator || {
                    title: title ?? namedSecretTitle,
                  },
                }),
          },
        },
      },
      session,
    );
    if (!response.ok) throw new Error("Secret find was denied by the broker.");
    let envelope: {
      jsonrpc?: unknown;
      id?: unknown;
      result?: {
        isError?: unknown;
        content?: Array<{ type?: unknown; text?: unknown }>;
      };
      error?: unknown;
    };
    try {
      envelope = (await response.json()) as typeof envelope;
    } catch {
      throw new Error("Broker returned an invalid secret find response.");
    }
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope))
      throw new Error("Broker returned an invalid secret find response.");
    const content = envelope.result?.content;
    const text =
      Array.isArray(content) &&
      content.length === 1 &&
      content[0]?.type === "text" &&
      typeof content[0].text === "string"
        ? content[0].text
        : undefined;
    if ("error" in envelope)
      throw new Error("Secret find was denied by the broker.");
    if (
      envelope.jsonrpc === "2.0" &&
      envelope.id === 1 &&
      envelope.result?.isError === true &&
      args.includes("--optional") &&
      ["secret_not_found", "secret_field_not_found"].includes(text || "")
    ) {
      console.log(JSON.stringify({ status: "optional_not_found" }));
      return;
    }
    if (
      envelope.jsonrpc === "2.0" &&
      envelope.id === 1 &&
      envelope.result?.isError === true &&
      text === "secret_store_unavailable" &&
      reference !== undefined &&
      store === undefined &&
      binding === undefined &&
      inputRef === undefined &&
      inputLocator === undefined &&
      title === undefined &&
      loginLocator === undefined
    ) {
      const localCompanion = await companionBindingForAlias(
        session,
        alias,
        "bitwarden-password-manager",
      );
      if (localCompanion?.read) {
        const localResult = await resolveBitwardenPasswordManagerFind(
          session,
          alias,
          reference,
          localCompanion.binding,
        );
        console.log(JSON.stringify(localResult));
        return;
      }
    }
    if (
      envelope.jsonrpc === "2.0" &&
      envelope.id === 1 &&
      envelope.result?.isError === true &&
      text === "secret_store_unavailable" &&
      reference !== undefined &&
      store === undefined &&
      binding === undefined &&
      inputRef === undefined &&
      inputLocator === undefined &&
      title === undefined &&
      loginLocator === undefined
    ) {
      const localCompanion = await companionBindingForAlias(
        session,
        alias,
        "onepassword-service-account",
      );
      if (localCompanion?.read) {
        const localResult = await resolveOnePasswordServiceAccountFind(
          session,
          alias,
          reference,
          localCompanion.binding,
        );
        console.log(JSON.stringify(localResult));
        return;
      }
    }
    if (
      envelope.jsonrpc === "2.0" &&
      envelope.id === 1 &&
      envelope.result?.isError === true &&
      text === "secret_store_unavailable" &&
      reference !== undefined &&
      store === undefined &&
      binding === undefined &&
      inputRef === undefined &&
      inputLocator === undefined &&
      title === undefined &&
      loginLocator === undefined
    ) {
      const localCompanion = await companionBindingForAlias(
        session,
        alias,
        "lastpass",
      );
      if (localCompanion?.read) {
        const localResult = await resolveLastPassFind(
          session,
          alias,
          reference,
          localCompanion.binding,
        );
        console.log(JSON.stringify(localResult));
        return;
      }
    }
    if (!text || envelope.result?.isError)
      throw new Error("Secret find was denied by the broker.");
    let result: unknown;
    try {
      result = JSON.parse(text);
    } catch {
      throw new Error("Broker returned an invalid secret find response.");
    }
    if (
      !result ||
      typeof result !== "object" ||
      (result as { status?: unknown }).status !== "available" ||
      typeof (result as { provider?: unknown }).provider !== "string" ||
      typeof (result as { reference?: unknown }).reference !== "string"
    )
      throw new Error("Broker returned an invalid secret find response.");
    const safeResult = {
      status: "available",
      provider: (result as { provider: string }).provider,
      reference: (result as { reference: string }).reference,
    };
    console.log(JSON.stringify(safeResult));
    return;
  }
  if (command === "request") {
    const requestOptions = [
      "--alias",
      "--url",
      "--method",
      "--data",
      "--stdin",
      "--server",
    ];
    if (
      requestOptions.some(
        (flag) => args.filter((arg) => arg === flag).length > 1,
      )
    )
      throw new Error("Use each request option at most once.");
    const data = option("data");
    const stdinMode = args.includes("--stdin");
    if (stdinMode && data !== undefined)
      throw new Error("Use either --stdin or --data, not both.");
    if (stdinMode && process.stdin.isTTY)
      throw new Error("--stdin requires piped JSON input.");
    let headers: Record<string, string> | undefined;
    let body: unknown;
    if (stdinMode) {
      const input = await readRequestStdin();
      if (
        !input ||
        typeof input !== "object" ||
        Array.isArray(input) ||
        Object.keys(input).some((key) => key !== "headers" && key !== "body")
      )
        throw new Error("Request input must contain only headers and body.");
      const requestInput = input as { headers?: unknown; body?: unknown };
      if (Object.hasOwn(requestInput, "headers"))
        headers = validateRequestHeaders(requestInput.headers);
      if (Object.hasOwn(requestInput, "body")) {
        if (typeof requestInput.body !== "string")
          throw new Error("Request body must be a text string.");
        if (
          new TextDecoder("utf-8", { fatal: true }).decode(
            Buffer.from(requestInput.body, "utf8"),
          ) !== requestInput.body
        )
          throw new Error("Request body must contain valid Unicode text.");
        body = requestInput.body;
      }
      if (
        typeof body === "string" &&
        !Object.keys(headers || {}).some(
          (name) => name.toLowerCase() === "content-type",
        )
      )
        headers = {
          ...(headers || {}),
          "Content-Type": "text/plain;charset=UTF-8",
        };
    } else if (data !== undefined) {
      try {
        JSON.parse(data);
      } catch {
        throw new Error("--data must be JSON.");
      }
      body = data;
      headers = { "Content-Type": "application/json" };
    }
    const response = await brokerProxyWithCapability({
      secret_alias: option("alias"),
      url: option("url"),
      method: option("method") || "GET",
      ...(body === undefined ? {} : { body }),
      ...(headers === undefined ? {} : { headers }),
    });
    const text = await response.text();
    console.log(text);
    if (!response.ok) process.exitCode = 1;
    return;
  }
  if (command === "mcp") {
    const input = createInterface({
      input: process.stdin,
      crlfDelay: Infinity,
    });
    const closeInputOnAbort = () => input.close();
    operation.signal.addEventListener("abort", closeInputOnAbort, {
      once: true,
    });
    try {
      for await (const line of input) {
        if (Buffer.byteLength(line) > 65536)
          throw new Error("MCP request exceeds size limit.");
        let value: unknown;
        try {
          value = JSON.parse(line);
        } catch {
          console.log(
            JSON.stringify({
              jsonrpc: "2.0",
              id: null,
              error: { code: -32700, message: "Parse error" },
            }),
          );
          continue;
        }
        const id =
          value && typeof value === "object" && "id" in value
            ? (value as { id: unknown }).id
            : undefined;
        try {
          const session = await credentials();
          const response = await broker("/mcp", value, session);
          operation.signal.throwIfAborted();
          const text = await response.text();
          if (response.ok) {
            if (text) {
              let localResponse: string | null = null;
              try {
                localResponse = await localCompanionResponse(
                  session,
                  value,
                  JSON.parse(text),
                  "bitwarden-password-manager",
                );
                if (!localResponse)
                  localResponse = await localCompanionResponse(
                    session,
                    value,
                    JSON.parse(text),
                    "onepassword-service-account",
                  );
                if (!localResponse)
                  localResponse = await localCompanionResponse(
                    session,
                    value,
                    JSON.parse(text),
                    "lastpass",
                  );
              } catch (error) {
                if (
                  error instanceof Error &&
                  (error.message.startsWith("bitwarden_password_manager_") ||
                    error.message.startsWith("onepassword_service_account_") ||
                    error.message.startsWith("lastpass_"))
                ) {
                  console.error(
                    "Local provider companion could not complete the authorized read.",
                  );
                  if (id !== undefined)
                    console.log(
                      JSON.stringify({
                        jsonrpc: "2.0",
                        id,
                        error: {
                          code: -32003,
                          message: "Local companion unavailable",
                        },
                      }),
                    );
                  continue;
                }
              }
              console.log(localResponse ?? text);
            }
          } else if (text && JSON.parse(text).jsonrpc === "2.0")
            console.log(text);
          else throw new Error("Broker rejected the request.");
        } catch {
          if (operation.signal.aborted) {
            console.error(
              "Operation cancelled; the request may have reached the broker, so reconcile its status before retrying.",
            );
            if (id !== undefined)
              console.log(
                JSON.stringify({
                  jsonrpc: "2.0",
                  id,
                  error: {
                    code: -32002,
                    message:
                      "Operation cancelled; the remote outcome may be unknown",
                  },
                }),
              );
            process.exitCode = signalExitCode || 130;
            return;
          }
          console.error(
            "Broker authorization or transport failed. Verify your login or workload identity.",
          );
          if (id !== undefined)
            console.log(
              JSON.stringify({
                jsonrpc: "2.0",
                id,
                error: {
                  code: -32001,
                  message: "Broker authorization or transport failed",
                },
              }),
            );
        }
      }
    } finally {
      operation.signal.removeEventListener("abort", closeInputOnAbort);
      input.close();
    }
    if (operation.signal.aborted) {
      console.error("Operation cancelled while waiting for MCP input.");
      process.exitCode = signalExitCode || 130;
    }
    return;
  }
  throw new Error("Unknown command. Run agentsecret --help.");
}
main().catch((error) => {
  if (operation.signal.aborted) {
    if (command === "request" && !proxyCapabilityRedemptionStarted)
      console.error(
        "Operation cancelled before proxy-capability redemption; no provider request was submitted.",
      );
    else
      console.error(
        "Operation cancelled; a request outcome may be unknown. A secret write's operation ID, if any, is saved; rerun the same command with the same target and value to check its receipt before starting another operation.",
      );
    process.exitCode = signalExitCode || 130;
    return;
  }
  console.error(error instanceof Error ? error.message : "Operation failed.");
  process.exitCode = 1;
});
