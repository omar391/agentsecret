#!/usr/bin/env node
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const cli = join(root, "dist", "cli.mjs");
const alias = "CODEX_HOST";
const serverName = "agentsecret";
const allowedUrl = "https://api.github.com/check";
const deniedUrl = "https://denied.github.com/check";
const issuer = "https://token.actions.githubusercontent.com";
const subject = "repo:example/repo:ref:refs/heads/main";
const ref = "refs/heads/main";
const repositoryId = "123";
const codexTimeoutMs = 150_000;
const CODEX_PROXY_TOOL_NAME = "proxy_http_request";

let liveRuntime;

function isPlainRecord(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validSchemaNode(schema) {
  if (!isPlainRecord(schema)) return false;
  if (schema.required !== undefined) {
    if (
      !Array.isArray(schema.required) ||
      schema.required.some((key) => typeof key !== "string" || !key) ||
      new Set(schema.required).size !== schema.required.length
    )
      return false;
  }
  if (schema.properties !== undefined) {
    if (!isPlainRecord(schema.properties)) return false;
    for (const child of Object.values(schema.properties)) {
      if (!validSchemaNode(child)) return false;
    }
  }
  if (schema.additionalProperties !== undefined) {
    const additional = schema.additionalProperties;
    if (
      additional !== true &&
      additional !== false &&
      !validSchemaNode(additional)
    )
      return false;
  }
  if (schema.items !== undefined && !validSchemaNode(schema.items))
    return false;
  if (schema.enum !== undefined && !Array.isArray(schema.enum)) return false;
  if (schema.minLength !== undefined && !Number.isInteger(schema.minLength))
    return false;
  if (schema.maxLength !== undefined && !Number.isInteger(schema.maxLength))
    return false;
  if (schema.pattern !== undefined) {
    if (typeof schema.pattern !== "string") return false;
    try {
      new RegExp(schema.pattern);
    } catch {
      return false;
    }
  }
  if (
    schema.type !== "object" &&
    (schema.properties !== undefined ||
      schema.required !== undefined ||
      schema.additionalProperties !== undefined)
  )
    return false;
  if (schema.type !== "array" && schema.items !== undefined) return false;
  if (
    schema.type !== "string" &&
    (schema.minLength !== undefined ||
      schema.maxLength !== undefined ||
      schema.pattern !== undefined)
  )
    return false;
  if (schema.type !== undefined) {
    if (
      typeof schema.type !== "string" ||
      ![
        "object",
        "array",
        "string",
        "number",
        "integer",
        "boolean",
        "null",
      ].includes(schema.type)
    )
      return false;
  }
  return true;
}

function schemaValueMatches(value, schema) {
  if (!isPlainRecord(schema)) return false;
  if (
    Array.isArray(schema.enum) &&
    !schema.enum.some((candidate) => Object.is(candidate, value))
  )
    return false;
  if (schema.type === undefined) return true;
  if (schema.type === "object") {
    if (!isPlainRecord(value)) return false;
    for (const key of schema.required || []) {
      if (!Object.hasOwn(value, key)) return false;
    }
    const properties = isPlainRecord(schema.properties)
      ? schema.properties
      : {};
    for (const key of Object.keys(value)) {
      if (Object.hasOwn(properties, key)) {
        if (!schemaValueMatches(value[key], properties[key])) return false;
        continue;
      }
      if (schema.additionalProperties === false) return false;
      if (isPlainRecord(schema.additionalProperties)) {
        if (!schemaValueMatches(value[key], schema.additionalProperties))
          return false;
      } else if (schema.additionalProperties !== true) {
        return false;
      }
    }
    return true;
  }
  if (schema.type === "array") {
    return (
      Array.isArray(value) &&
      (schema.items === undefined ||
        value.every((item) => schemaValueMatches(item, schema.items)))
    );
  }
  if (schema.type === "string") {
    if (typeof value !== "string") return false;
    if (schema.minLength !== undefined && value.length < schema.minLength)
      return false;
    if (schema.maxLength !== undefined && value.length > schema.maxLength)
      return false;
    if (
      typeof schema.pattern === "string" &&
      !new RegExp(schema.pattern).test(value)
    )
      return false;
    return true;
  }
  if (schema.type === "number" || schema.type === "integer") {
    return (
      typeof value === "number" &&
      Number.isFinite(value) &&
      (schema.type === "number" || Number.isInteger(value))
    );
  }
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "null") return value === null;
  return false;
}

function advertisedProxySchema(tools) {
  if (!Array.isArray(tools))
    throw new Error("codex_host_advertised_tools_invalid");
  const matches = tools.filter(
    (tool) => isPlainRecord(tool) && tool.name === CODEX_PROXY_TOOL_NAME,
  );
  if (matches.length !== 1)
    throw new Error("codex_host_advertised_tool_missing");
  const schema = matches[0].inputSchema;
  if (
    !isPlainRecord(schema) ||
    schema.type !== "object" ||
    schema.additionalProperties !== false ||
    !Array.isArray(schema.required) ||
    schema.required.length === 0 ||
    schema.required.some((key) => typeof key !== "string" || !key) ||
    new Set(schema.required).size !== schema.required.length ||
    !isPlainRecord(schema.properties) ||
    schema.required.some((key) => !Object.hasOwn(schema.properties, key)) ||
    Object.values(schema.properties).some((child) => !isPlainRecord(child)) ||
    !validSchemaNode(schema)
  )
    throw new Error("codex_host_advertised_schema_invalid");
  return schema;
}

export function codexExecutable(env = process.env) {
  const configured = env && typeof env === "object" ? env.CODEX_BIN : undefined;
  return typeof configured === "string" && configured.trim()
    ? configured.trim()
    : "codex";
}

export function buildAppServerInvocation({
  cli,
  origin,
  configDir,
  execPath = process.execPath,
  env = process.env,
}) {
  if (
    typeof cli !== "string" ||
    !cli.trim() ||
    typeof origin !== "string" ||
    !origin.trim() ||
    typeof configDir !== "string" ||
    !configDir.trim() ||
    typeof execPath !== "string" ||
    !execPath.trim()
  )
    throw new Error("codex_host_invocation_invalid");
  let parsedOrigin;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    throw new Error("codex_host_invocation_invalid");
  }
  if (
    !["http:", "https:"].includes(parsedOrigin.protocol) ||
    parsedOrigin.username ||
    parsedOrigin.password ||
    parsedOrigin.pathname !== "/" ||
    parsedOrigin.search ||
    parsedOrigin.hash
  )
    throw new Error("codex_host_invocation_invalid");
  return {
    executable: codexExecutable(env),
    args: [
      "app-server",
      "--listen",
      "stdio://",
      "-c",
      "mcp_servers.agentsecret.command=" + JSON.stringify(execPath),
      "-c",
      "mcp_servers.agentsecret.args=" +
        JSON.stringify([cli, "mcp", "--server", parsedOrigin.origin]),
      "-c",
      "mcp_servers.agentsecret.env={ AGENTSECRET_CONFIG_DIR = " +
        JSON.stringify(configDir) +
        " }",
    ],
  };
}

export function validateCodexToolInvocation({ tools, calls } = {}) {
  const schema = advertisedProxySchema(tools);
  if (!Array.isArray(calls) || calls.length === 0)
    throw new Error("codex_host_tool_invocations_incomplete");
  for (const call of calls) {
    if (!isPlainRecord(call) || call.name !== CODEX_PROXY_TOOL_NAME)
      throw new Error("codex_host_unexpected_tool_invocation");
    if (
      !Object.hasOwn(call, "arguments") ||
      !isPlainRecord(call.arguments) ||
      !schemaValueMatches(call.arguments, schema)
    )
      throw new Error("codex_host_invalid_tool_arguments");
  }
  return {
    status: "validated",
    advertisedTool: CODEX_PROXY_TOOL_NAME,
    advertisedSchema: schema,
    validatedCalls: calls.length,
  };
}

export function advertisedCodexToolsFromStatus(status) {
  if (!isPlainRecord(status))
    throw new Error("codex_host_advertised_tools_invalid");
  const servers = status.data;
  if (!Array.isArray(servers) || servers.length !== 1)
    throw new Error("codex_host_advertised_tools_invalid");
  const server = servers[0];
  if (
    !isPlainRecord(server) ||
    server.name !== serverName ||
    server.runtimeStatus !== "connected" ||
    !isPlainRecord(server.tools)
  )
    throw new Error("codex_host_advertised_tools_invalid");
  const tools = Object.values(server.tools).map((tool) => ({
    name: tool?.name,
    inputSchema: tool?.inputSchema,
  }));
  const schema = advertisedProxySchema(tools);
  return { server, tools, schema };
}

export function validateCodexToolResult(result, expected) {
  if (!isPlainRecord(result) || !Array.isArray(result.content))
    throw new Error("codex_host_tool_result_invalid");
  if (expected === "allowed") {
    if (result.isError === true)
      throw new Error("codex_host_policy_enforcement_failed");
    return { status: "allowed" };
  }
  if (expected === "denied") {
    if (result.isError !== true)
      throw new Error("codex_host_policy_enforcement_failed");
    const codes = result.content
      .map((part) =>
        typeof part?.text === "string"
          ? /^([a-z][a-z0-9_]{1,79})$/.exec(part.text.trim())?.[1]
          : undefined,
      )
      .filter(Boolean);
    if (!codes.includes("policy_denied"))
      throw new Error("codex_host_policy_enforcement_failed");
    return { status: "policy_denied", codes };
  }
  throw new Error("codex_host_tool_result_invalid");
}

export function buildAppServerRequests({ threadId }) {
  if (typeof threadId !== "string" || !threadId)
    throw new Error("codex_host_app_server_thread_invalid");
  return {
    initialize: {
      method: "initialize",
      params: {
        clientInfo: {
          name: "agentsecret-codex-host-acceptance",
          title: "AgentSecret Codex Host Acceptance",
          version: "0.1.0",
        },
      },
    },
    threadStart: {
      method: "thread/start",
      params: { cwd: process.cwd(), ephemeral: true },
    },
    statusList: {
      method: "mcpServerStatus/list",
      params: {
        serverName,
        threadId,
        detail: "toolsAndAuthOnly",
      },
    },
    allowedCall: {
      method: "mcpServer/tool/call",
      params: {
        server: serverName,
        threadId,
        tool: CODEX_PROXY_TOOL_NAME,
        arguments: {
          secret_alias: alias,
          url: allowedUrl,
          method: "GET",
        },
      },
    },
    deniedCall: {
      method: "mcpServer/tool/call",
      params: {
        server: serverName,
        threadId,
        tool: CODEX_PROXY_TOOL_NAME,
        arguments: {
          secret_alias: alias,
          url: deniedUrl,
          method: "GET",
        },
      },
    },
  };
}

function safeCallPreview(call) {
  return {
    name: typeof call?.name === "string" ? call.name : "unknown",
    alias: call?.alias,
    host: call?.host,
    method: typeof call?.method === "string" ? call.method : undefined,
    argumentKeys: isPlainRecord(call?.arguments)
      ? Object.keys(call.arguments).sort()
      : [],
  };
}

async function loadLiveRuntime() {
  const [childProcess, assertion, http, crypto, fs, jose, helpers] =
    await Promise.all([
      import("node:child_process"),
      import("node:assert/strict"),
      import("node:http"),
      import("node:crypto"),
      import("node:fs/promises"),
      import("jose"),
      import("../tests/helpers.mjs"),
    ]);
  return {
    spawn: childProcess.spawn,
    execFileSync: childProcess.execFileSync,
    assert: assertion.default,
    createServer: http.createServer,
    createHash: crypto.createHash,
    mkdtemp: fs.mkdtemp,
    mkdir: fs.mkdir,
    rm: fs.rm,
    exportJWK: jose.exportJWK,
    generateKeyPair: jose.generateKeyPair,
    fixture: helpers.fixture,
    testOrigin: helpers.origin,
    random: helpers.random,
  };
}
function capturedChild(executable, args, options = {}) {
  const child = liveRuntime.spawn(executable, args, {
    ...options,
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const closed = new Promise((resolveClose, rejectClose) => {
    child.once("error", rejectClose);
    child.once("close", (code, signal) =>
      resolveClose({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
  });
  return { child, closed };
}

function terminate(child, signal = "SIGTERM") {
  if (!child?.pid) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch {
    try {
      child.kill(signal);
    } catch {}
  }
}

async function runChild(executable, args, options = {}) {
  const { child, closed } = capturedChild(executable, args, options);
  let killTimer;
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    terminate(child);
    killTimer = setTimeout(() => terminate(child, "SIGKILL"), 5_000);
    killTimer.unref();
  }, 30_000);
  try {
    const result = await closed;
    if (timedOut) throw new Error("codex_host_child_timeout");
    return result;
  } finally {
    clearTimeout(timer);
    clearTimeout(killTimer);
  }
}

function proxyServer(edgeRef, originRef, observations) {
  return liveRuntime.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", async () => {
      try {
        const body = Buffer.concat(chunks);
        if (req.url === "/oauth/device/code" && req.method === "POST") {
          const request = JSON.parse(body.toString("utf8"));
          observations.deviceRequest = {
            client_id: request.client_id,
            tenant: request.tenant,
            aliases: request.aliases,
            scope: request.scope,
          };
        }
        if (req.url === "/mcp" && req.method === "POST") {
          for (const line of body.toString("utf8").split("\n")) {
            if (!line) continue;
            let message;
            try {
              message = JSON.parse(line);
            } catch {
              continue;
            }
            observations.mcpMethods.push(message.method || "notification");
            if (message.method === "tools/call") {
              const args = message.params?.arguments;
              const call = {
                name:
                  typeof message.params?.name === "string"
                    ? message.params.name
                    : "unknown",
                arguments: args,
              };
              if (isPlainRecord(args)) {
                if (args.secret_alias === alias) call.alias = alias;
                if (typeof args.url === "string") {
                  try {
                    call.host = new URL(args.url).hostname;
                    call.method = args.method || "GET";
                  } catch {}
                }
              }
              observations.calls.push(call);
            }
          }
        }
        const edge = edgeRef.current;
        const origin = originRef.current;
        if (!edge || !origin) throw new Error("fixture_not_ready");
        const upstream = await edge.fetch(origin + req.url, {
          method: req.method,
          headers: req.headers,
          body: ["GET", "HEAD"].includes(req.method || "GET")
            ? undefined
            : body,
        });
        const responseBody = Buffer.from(await upstream.arrayBuffer());
        if (req.url === "/mcp" && req.method === "POST") {
          for (const line of responseBody.toString("utf8").split("\n")) {
            if (!line) continue;
            try {
              const message = JSON.parse(line);
              if (Array.isArray(message.result?.tools)) {
                observations.tools = message.result.tools.map((tool) => ({
                  name: tool?.name,
                  inputSchema: tool?.inputSchema,
                }));
                observations.toolNames = message.result.tools
                  .map((tool) => tool?.name)
                  .filter((name) => typeof name === "string");
              }
              if (message.result?.isError === true) {
                observations.toolErrors.push("tool_result_error");
                for (const part of message.result.content || []) {
                  if (typeof part?.text === "string") {
                    const code = /^([a-z][a-z0-9_]{1,79})$/.exec(
                      part.text.trim(),
                    )?.[1];
                    if (code) observations.toolErrors.push(code);
                  }
                }
              }
              if (message.error && Number.isInteger(message.error.code))
                observations.toolErrors.push(
                  `jsonrpc_error_${message.error.code}`,
                );
            } catch {}
          }
        }
        if (req.url === "/oauth/device/code" && req.method === "POST") {
          try {
            const grant = JSON.parse(responseBody.toString("utf8"));
            observations.deviceUserCodeHash = liveRuntime
              .createHash("sha256")
              .update(String(grant.user_code || ""))
              .digest("hex");
          } catch {}
        }
        res.writeHead(upstream.status, Object.fromEntries(upstream.headers));
        res.end(responseBody);
      } catch {
        res.writeHead(500);
        res.end();
      }
    });
  });
}

async function listen(server) {
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function closeServer(server) {
  if (!server?.listening) return;
  server.closeAllConnections?.();
  await new Promise((resolveClose) => server.close(resolveClose));
}

async function waitForDeviceCode(child, timeoutMs = 20_000) {
  return await new Promise((resolveCode, rejectCode) => {
    let buffered = "";
    const finish = (callback, value) => {
      clearTimeout(timer);
      child.stderr.off("data", onData);
      child.off("close", onClose);
      callback(value);
    };
    const onData = (chunk) => {
      buffered += chunk.toString("utf8");
      const match = /Confirm code:\s*([A-Z0-9_-]+)/.exec(buffered);
      if (match) finish(resolveCode, match[1]);
    };
    const onClose = () => finish(rejectCode, new Error("device_login_failed"));
    const timer = setTimeout(() => {
      terminate(child);
      finish(rejectCode, new Error("codex_host_device_code_timeout"));
    }, timeoutMs);
    child.stderr.on("data", onData);
    child.once("close", onClose);
  });
}

async function runCodex(executable, args, options) {
  const { child, closed } = capturedChild(executable, args, options);
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    terminate(child);
    setTimeout(() => terminate(child, "SIGKILL"), 5_000).unref();
  }, codexTimeoutMs);
  try {
    return { ...(await closed), timedOut };
  } finally {
    clearTimeout(timer);
  }
}

export class AppServerSession {
  constructor(
    executable,
    args,
    options,
    credentials,
    runtime = liveRuntime,
    { timeoutMs = codexTimeoutMs } = {},
  ) {
    this.executable = executable;
    this.args = args;
    this.options = options;
    this.credentials = credentials;
    this.runtime = runtime;
    this.timeoutMs = timeoutMs;
    this.nextId = 1;
    this.pending = new Map();
    this.notifications = [];
    this.buffer = "";
    this.stdout = "";
    this.stderr = "";
    this.timedOut = false;
  }

  start() {
    this.child = this.runtime.spawn(this.executable, this.args, {
      ...this.options,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.closed = new Promise((resolveClose, rejectClose) => {
      this.child.once("error", rejectClose);
      this.child.once("close", (code, signal) =>
        resolveClose({ code, signal }),
      );
    });
    this.outputFailure = null;
    this.child.stdout.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      this.stdout += text;
      try {
        assertNoCredentialReflection(text, this.credentials);
      } catch (error) {
        this.outputFailure = error;
        this.settlePending(error);
        void this.close().catch(() => {});
        return;
      }
      this.buffer += text;
      let index;
      while ((index = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, index);
        this.buffer = this.buffer.slice(index + 1);
        this.receiveLine(line);
      }
    });
    this.child.stderr.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      this.stderr += text;
      try {
        assertNoCredentialReflection(text, this.credentials);
      } catch (error) {
        this.outputFailure = error;
        this.settlePending(error);
        void this.close().catch(() => {});
      }
    });
    this.child.stdin.on("error", () => {
      this.handleInputFailure();
    });
    this.timeout = setTimeout(() => {
      this.timedOut = true;
      this.close();
    }, this.timeoutMs);
  }

  receiveLine(line) {
    if (!line) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      this.notifications.push({ parseError: true });
      return;
    }
    if (
      isPlainRecord(message) &&
      message.id !== undefined &&
      this.pending.has(message.id)
    ) {
      const entry = this.pending.get(message.id);
      this.pending.delete(message.id);
      clearTimeout(entry.timer);
      entry.resolve(message);
      return;
    }
    this.notifications.push({
      method: isPlainRecord(message) ? message.method : undefined,
    });
  }

  settlePending(error) {
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer);
      this.pending.delete(entry.id);
      entry.reject(error);
    }
    this.pending.clear();
  }

  handleInputFailure() {
    if (this.inputFailure) return;
    this.inputFailure = new Error("codex_host_app_server_unavailable");
    this.settlePending(this.inputFailure);
    void this.close().catch(() => {});
  }

  request({ method, params }) {
    if (!this.child?.stdin?.writable)
      return Promise.reject(new Error("codex_host_app_server_unavailable"));
    if (this.outputFailure) return Promise.reject(this.outputFailure);
    if (this.inputFailure) return Promise.reject(this.inputFailure);
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error("codex_host_app_server_request_timeout"));
      }, this.timeoutMs);
      timer.unref?.();
      this.pending.set(id, { id, resolve, reject, timer });
      this.child.stdin.write(
        JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n",
        (error) => {
          if (error) {
            clearTimeout(timer);
            if (this.pending.get(id)) {
              this.pending.delete(id);
              reject(new Error("codex_host_app_server_unavailable"));
            }
          }
        },
      );
    });
  }

  async close(options = {}) {
    if (this.timeout) clearTimeout(this.timeout);
    if (this.closing) return this.closePromise ?? this.closed;
    this.settlePending(new Error("codex_host_app_server_unavailable"));
    this.closing = true;
    const failure = this.outputFailure;
    terminate(this.child, "SIGKILL");
    this.closePromise = this.closed.then(
      (result) => {
        if (failure) throw failure;
        return result;
      },
      (error) => {
        if (failure) throw failure;
        throw error;
      },
    );
    return this.closePromise;
  }
}

function assertNoCredentialReflection(value, credentials) {
  for (const credential of credentials) {
    if (credential && value.includes(credential))
      throw new Error("codex_host_secret_reflection");
  }
}

function safeCodexMessagePreview(stdout) {
  const messages = [];
  for (const line of stdout.split(/\r?\n/)) {
    if (!line) continue;
    try {
      const event = JSON.parse(line);
      if (event.type !== "item.completed") continue;
      const item = event.item;
      if (!item || !["assistant_message", "agent_message"].includes(item.type))
        continue;
      if (typeof item.text === "string") messages.push(item.text);
      if (Array.isArray(item.content))
        for (const part of item.content)
          if (part && typeof part.text === "string") messages.push(part.text);
    } catch {}
  }
  return messages
    .join(" ")
    .replace(/Bearer\s+[A-Za-z0-9._-]{8,}/gi, "Bearer [redacted]")
    .replace(/\beyJ[A-Za-z0-9._-]{20,}\b/g, "[redacted-token]")
    .slice(0, 240);
}

async function approveDeviceWithFreshReview(fixtureState, userCode, session) {
  const initial = await fixtureState.approveDevice(userCode, session, alias);
  if (initial.status === 200) return { staleReviewRefreshed: false };
  const error = await initial.json().catch(() => ({}));
  if (error.error !== "consent_stale")
    throw new Error("codex_host_device_consent_failed");

  // A stale page is rejected, never auto-approved. Refresh and check the full
  // synthetic consent scope before submitting a new consent snapshot.
  const review = await fixtureState.call(
    "/device?code=" + encodeURIComponent(userCode),
    { headers: { Cookie: "agentsecret_session=" + session } },
  );
  if (review.status !== 200)
    throw new Error("codex_host_device_consent_refresh_failed");
  const html = await review.text();
  if (
    !html.includes("Client: agentsecret-cli") ||
    !html.includes("CODEX_HOST") ||
    !html.includes("api.github.com") ||
    !html.includes("secrets:proxy") ||
    !html.includes("secrets:read")
  )
    throw new Error("codex_host_device_consent_scope_changed");
  const consentId = html.match(/name="consent_id" value="([^"]+)"/)?.[1];
  if (!consentId) throw new Error("codex_host_device_consent_refresh_failed");
  const refreshed = await fixtureState.a.fetch(
    liveRuntime.testOrigin + "/api/device/approve",
    {
      method: "POST",
      headers: {
        Cookie: "agentsecret_session=" + session,
        Origin: liveRuntime.testOrigin,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        user_code: userCode,
        aliases: alias,
        consent_id: consentId,
      }),
    },
  );
  if (refreshed.status !== 200)
    throw new Error("codex_host_device_consent_refresh_failed");
  return { staleReviewRefreshed: true };
}

async function main() {
  liveRuntime = await loadLiveRuntime();
  const {
    execFileSync,
    assert,
    createHash,
    mkdtemp,
    mkdir,
    rm,
    exportJWK,
    generateKeyPair,
    fixture,
    random,
  } = liveRuntime;
  let codexVersion;
  let phase = "codex_cli_version";
  try {
    codexVersion = execFileSync(codexExecutable(process.env), ["--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 10_000,
    }).trim();
  } catch {
    throw new Error("codex_host_cli_unavailable");
  }

  const signing = await generateKeyPair("RS256");
  const jwk = await exportJWK(signing.publicKey);
  jwk.kid = "codex-host-synthetic";
  const rule = {
    issuer,
    subject,
    ref,
    repositoryId,
    audience: "pending",
    tenant: "default",
    scopes: ["secrets:read", "secrets:proxy"],
    aliases: [alias],
  };
  const connectVaultId = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
  const connectItemId = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
  const connectToken = "synthetic-codex-connect-" + random();
  const syntheticCredential = "synthetic-codex-credential-" + random();
  const observations = {
    allowedDispatches: 0,
    providerReads: 0,
    connectAuthMatches: null,
    calls: [],
    mcpMethods: [],
    toolNames: [],
    tools: [],
    toolErrors: [],
  };
  const edgeRef = { current: null };
  const originRef = { current: null };
  const server = proxyServer(edgeRef, originRef, observations);
  let fixtureState;
  let scratch;
  let customerSession;
  let loginProcess;
  let sessionMayExist = false;
  let remoteLogoutSucceeded = false;

  try {
    phase = "fixture_setup";
    originRef.current = await listen(server);
    rule.audience = originRef.current;
    fixtureState = await fixture({
      bindings: {
        PUBLIC_ORIGIN: originRef.current,
        WORKLOAD_TRUST: JSON.stringify([rule]),
      },
      outbound: async (request) => {
        if (request.url === `${issuer}/.well-known/jwks`)
          return Response.json({ keys: [jwk] });
        if (
          request.url ===
            `https://connect.1password.com/v1/vaults/${connectVaultId}/items/${connectItemId}` &&
          request.method === "GET"
        ) {
          observations.providerReads += 1;
          observations.connectAuthMatches =
            request.headers.get("Authorization") === `Bearer ${connectToken}`;
          if (!observations.connectAuthMatches)
            return Response.json({ error: "denied" }, { status: 401 });
          return Response.json({
            id: connectItemId,
            vault: { id: connectVaultId },
            fields: [{ id: "password", value: syntheticCredential }],
          });
        }
        if (request.url === allowedUrl && request.method === "GET") {
          observations.allowedDispatches += 1;
          assert.equal(
            request.headers.get("Authorization"),
            `Bearer ${syntheticCredential}`,
          );
          return Response.json({
            ok: true,
            reflected: syntheticCredential,
          });
        }
        throw new Error("unexpected_outbound_request");
      },
    });
    edgeRef.current = fixtureState.a;
    phase = "connect_fixture_setup";
    const connection = await fixtureState.admin("/api/user/vaults", {
      config: {
        type: "onepassword-connect",
        accessToken: connectToken,
        apiUrl: "https://connect.1password.com",
        vaultId: connectVaultId,
      },
    });
    if (connection.status !== 200)
      throw new Error("codex_host_synthetic_provider_setup_failed");
    await fixtureState.policy(alias, {
      secretId: `${connectItemId}#password`,
      allowedDomains: ["api.github.com"],
      allowedMethods: ["GET"],
    });
    const scratchRoot = join(root, "tmp");
    await mkdir(scratchRoot, { recursive: true });
    scratch = await mkdtemp(join(scratchRoot, ".codex-host-"));
    const configDir = join(scratch, "agentsecret-config");

    await fixtureState.createAccount(
      "default",
      "Synthetic Codex Host Customer",
    );
    customerSession = await fixtureState.signIn("default");
    phase = "device_login";
    const login = capturedChild(
      process.execPath,
      [
        cli,
        "login",
        "--server",
        originRef.current,
        "--device",
        "--aliases",
        alias,
      ],
      {
        cwd: scratch,
        env: { ...process.env, AGENTSECRET_CONFIG_DIR: configDir },
      },
    );
    loginProcess = login.child;
    const userCode = await waitForDeviceCode(loginProcess);
    if (!/^[A-Z0-9_-]{12}$/.test(userCode))
      throw new Error("codex_host_device_code_invalid");
    if (
      observations.deviceUserCodeHash !==
      createHash("sha256").update(userCode).digest("hex")
    )
      throw new Error("codex_host_device_code_mismatch");
    const consent = await approveDeviceWithFreshReview(
      fixtureState,
      userCode,
      customerSession,
    );
    phase = "device_login_finish";
    sessionMayExist = true;
    const loginResult = await login.closed;
    if (loginResult.code !== 0)
      throw new Error("codex_host_device_enrollment_failed");

    phase = "codex_app_server";
    const invocation = buildAppServerInvocation({
      cli,
      origin: originRef.current,
      configDir,
      execPath: process.execPath,
    });
    const credentials = [customerSession, syntheticCredential, connectToken];
    const codexHome = join(scratch, "codex-home");
    await mkdir(codexHome, { recursive: true });
    const session = new AppServerSession(
      invocation.executable,
      invocation.args,
      {
        cwd: scratch,
        env: { ...process.env, CODEX_HOME: codexHome },
      },
      credentials,
    );
    session.start();
    const requests = {};
    let threadId;
    let advertised;
    let allowedResult;
    let deniedResult;
    try {
      const initializeResponse = await session.request({
        method: "initialize",
        params: {
          clientInfo: {
            name: "agentsecret-codex-host-acceptance",
            title: "AgentSecret Codex Host Acceptance",
            version: "0.1.0",
          },
        },
      });
      if (initializeResponse.error)
        throw new Error("codex_host_app_server_initialize_failed");
      const threadResponse = await session.request({
        method: "thread/start",
        params: { cwd: scratch, ephemeral: true },
      });
      if (threadResponse.error)
        throw new Error("codex_host_app_server_thread_start_failed");
      threadId = threadResponse.result?.thread?.id;
      if (typeof threadId !== "string" || !threadId)
        throw new Error("codex_host_app_server_thread_start_failed");
      const statusRequest = {
        method: "mcpServerStatus/list",
        params: {
          serverName,
          threadId,
          detail: "toolsAndAuthOnly",
        },
      };
      requests.statusList = statusRequest;
      const statusResponse = await session.request(statusRequest);
      if (statusResponse.error)
        throw new Error("codex_host_mcp_server_unavailable");
      advertised = advertisedCodexToolsFromStatus(statusResponse.result);
      requests.allowedCall = {
        method: "mcpServer/tool/call",
        params: {
          server: serverName,
          threadId,
          tool: CODEX_PROXY_TOOL_NAME,
          arguments: {
            secret_alias: alias,
            url: allowedUrl,
            method: "GET",
          },
        },
      };
      const allowedResponse = await session.request(requests.allowedCall);
      if (allowedResponse.error)
        throw new Error("codex_host_policy_enforcement_failed");
      allowedResult = validateCodexToolResult(
        allowedResponse.result,
        "allowed",
      );
      requests.deniedCall = {
        method: "mcpServer/tool/call",
        params: {
          server: serverName,
          threadId,
          tool: CODEX_PROXY_TOOL_NAME,
          arguments: {
            secret_alias: alias,
            url: deniedUrl,
            method: "GET",
          },
        },
      };
      const deniedResponse = await session.request(requests.deniedCall);
      if (deniedResponse.error)
        throw new Error("codex_host_policy_enforcement_failed");
      deniedResult = validateCodexToolResult(deniedResponse.result, "denied");
    } finally {
      await session.close();
    }
    if (session.timedOut) throw new Error("codex_host_run_timeout");
    phase = "codex_result_review";
    assertNoCredentialReflection(session.stdout + session.stderr, credentials);

    const toolValidation = validateCodexToolInvocation({
      tools: advertised.tools,
      calls: [requests.allowedCall.params, requests.deniedCall.params].map(
        (params) => ({
          name: params.tool,
          arguments: params.arguments,
        }),
      ),
    });
    const advertisedSchemaDigest = createHash("sha256")
      .update(JSON.stringify(toolValidation.advertisedSchema))
      .digest("hex");

    const allowedCalls = observations.calls.filter(
      (call) =>
        call.name === "proxy_http_request" &&
        call.alias === alias &&
        call.host === "api.github.com" &&
        call.method === "GET",
    ).length;
    const deniedCalls = observations.calls.filter(
      (call) =>
        call.name === "proxy_http_request" &&
        call.alias === alias &&
        call.host === "denied.github.com" &&
        call.method === "GET",
    ).length;
    if (allowedCalls !== 1 || deniedCalls !== 1) {
      process.stderr.write(
        JSON.stringify({
          codexVersion,
          mcpMethods: observations.mcpMethods,
          toolNames: observations.toolNames,
          toolCalls: observations.calls.map(safeCallPreview),
          providerReads: observations.providerReads,
          connectAuthMatches: observations.connectAuthMatches,
          allowedDispatches: observations.allowedDispatches,
          toolErrors: observations.toolErrors,
          advertisedSchemaDigest,
          appServerNotifications: session.notifications.length,
        }) + "\n",
      );
      throw new Error("codex_host_tool_invocations_incomplete");
    }
    if (observations.allowedDispatches !== 1) {
      process.stderr.write(
        JSON.stringify({
          codexVersion,
          allowedDispatches: observations.allowedDispatches,
          providerReads: observations.providerReads,
          connectAuthMatches: observations.connectAuthMatches,
          advertisedSchemaDigest,
          toolErrors: observations.toolErrors,
        }) + "\n",
      );
      throw new Error("codex_host_policy_enforcement_failed");
    }
    if (observations.providerReads !== 1)
      throw new Error("codex_host_provider_dispatch_count_mismatch");
    if (
      observations.calls.some(
        (call) =>
          call.name !== "proxy_http_request" ||
          call.alias !== alias ||
          (call.host !== "api.github.com" && call.host !== "denied.github.com"),
      )
    )
      throw new Error("codex_host_unexpected_tool_invocation");

    const logout = await runChild(
      process.execPath,
      [cli, "logout", "--remote"],
      {
        cwd: scratch,
        env: { ...process.env, AGENTSECRET_CONFIG_DIR: configDir },
      },
    );
    if (logout.code !== 0)
      throw new Error("codex_host_remote_revocation_failed");
    remoteLogoutSucceeded = true;
    phase = "complete";

    process.stdout.write(
      JSON.stringify({
        status: "passed",
        codexVersion,
        host: "Codex CLI",
        scenario: "synthetic local Worker",
        allowedCalls,
        deniedCalls,
        authorizedUpstreamDispatches: observations.allowedDispatches,
        providerReads: observations.providerReads,
        staleConsentPageRefreshed: consent.staleReviewRefreshed,
        remoteLogout: "passed",
        advertisedToolSchema: "validated",
        advertisedToolSchemaDigest: advertisedSchemaDigest,
        validatedToolCalls: toolValidation.validatedCalls,
        credentialReflection: "none",
      }) + "\n",
    );
  } catch (error) {
    const reason =
      error instanceof Error && /^codex_host_[a-z0-9_]+$/.test(error.message)
        ? error.message
        : "codex_host_acceptance_failed";
    const errorCode =
      error &&
      typeof error === "object" &&
      "code" in error &&
      typeof error.code === "string" &&
      /^[A-Z0-9_]+$/.test(error.code)
        ? error.code
        : undefined;
    process.stderr.write(
      JSON.stringify({
        result: reason,
        phase,
        errorName: error?.name,
        errorMessage: error?.message,
        errorStack: error?.stack?.split("\n").slice(0, 4).join(" | "),
        errorCode,
      }) + "\n",
    );
    process.exitCode = 1;
  } finally {
    if (loginProcess) terminate(loginProcess);
    if (sessionMayExist && !remoteLogoutSucceeded && scratch) {
      try {
        await runChild(process.execPath, [cli, "logout", "--remote"], {
          cwd: scratch,
          env: {
            ...process.env,
            AGENTSECRET_CONFIG_DIR: join(scratch, "agentsecret-config"),
          },
        });
      } catch {}
      // If remote revocation failed, still delete the synthetic local Keychain
      // entry. The disposable Worker is destroyed below, and the failure stays
      // visible through the nonzero acceptance result.
      try {
        await runChild(process.execPath, [cli, "logout"], {
          cwd: scratch,
          env: {
            ...process.env,
            AGENTSECRET_CONFIG_DIR: join(scratch, "agentsecret-config"),
          },
        });
      } catch {}
    }
    if (fixtureState) await fixtureState.dispose();
    await closeServer(server);
    if (scratch) await rm(scratch, { recursive: true, force: true });
    customerSession = "";
  }
}

const invokedDirectly =
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  main().catch((error) => {
    const location = String(error?.stack || "")
      .split("\n")
      .map((line) => /accept-codex-host\.mjs:(\d+):(\d+)/.exec(line))
      .find(Boolean);
    process.stderr.write(
      JSON.stringify({
        result: "codex_host_acceptance_failed",
        errorName: error?.name,
        location: location
          ? { line: Number(location[1]), column: Number(location[2]) }
          : undefined,
      }) + "\n",
    );
    process.exitCode = 1;
  });
}
