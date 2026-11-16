import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  rm,
  readFile,
  writeFile,
  utimes,
} from "node:fs/promises";
import { createServer, request as httpRequest } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { tmpdir } from "node:os";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import type { AuthorityKernel } from "../src/state/authority-kernel";
import type { Env } from "../src/types";
import { updateAccountProfile } from "../src/registry/store";
import { signInSession } from "../src/auth/sessions";
import { NodeAuthorityHost } from "../src/server/authority-host";
import type { SqliteAuthorityStorage } from "../src/server/authority-storage";
import { startNodeServer } from "../src/server/index";
import { toHeaders } from "../src/server/http";
import {
  applyRegistryMigrations,
  SqliteRegistryDatabase,
} from "../src/server/registry";

async function temporaryDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeoutMs = 10_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await condition()) return;
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

type AuthorityRuntimeProbe = {
  runtime(tenant: string): {
    kernel: AuthorityKernel;
    storage: SqliteAuthorityStorage;
    db: DatabaseSync;
  };
};

test("Node/SQLite registry returns committed RETURNING rows and serializes batches", async () => {
  const raw = new DatabaseSync(":memory:");
  raw.exec("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT NOT NULL)");
  const db = new SqliteRegistryDatabase(raw);
  const created = await db
    .prepare("INSERT INTO sample (value) VALUES (?) RETURNING id, value")
    .bind("created")
    .run<{ id: number; value: string }>();
  assert.equal(created.results[0]?.id, 1);
  assert.equal(created.results[0]?.value, "created");

  const first = db.batch([
    db.prepare("INSERT INTO sample (value) VALUES (?)").bind("first-a"),
    db.prepare("INSERT INTO sample (value) VALUES (?)").bind("first-b"),
  ]);
  const second = db.batch([
    db.prepare("INSERT INTO sample (value) VALUES (?)").bind("second-a"),
    db.prepare("INSERT INTO sample (value) VALUES (?)").bind("second-b"),
  ]);
  const ordinary = db
    .prepare("INSERT INTO sample (value) VALUES (?)")
    .bind("ordinary")
    .run();
  await Promise.all([first, second, ordinary]);
  const values = await db.prepare("SELECT value FROM sample ORDER BY id").all();
  assert.equal(values.results.length, 6);

  await assert.rejects(
    db.batch([
      db.prepare("INSERT INTO sample (value) VALUES (?)").bind("rollback"),
      db.prepare("INSERT INTO missing_table (value) VALUES (?)").bind("fail"),
    ]),
  );
  const count = await db
    .prepare("SELECT COUNT(*) AS count FROM sample")
    .first<{ count: number }>("count");
  assert.equal(count, 6);
  raw.close();
});

test("Node/SQLite server: second process sharing the data directory is rejected", async (t) => {
  const dir = await temporaryDir("agentsecret-node-lock-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const first = await startNodeServer({
    dataDir: dir,
    port: 0,
    env: {},
  });
  t.after(() => first.close());
  await assert.rejects(
    () => startNodeServer({ dataDir: dir, port: 0, env: {} }),
    /already running/,
  );
});

test("Node server releases startup resources after an occupied-port failure", async (t) => {
  const dir = await temporaryDir("agentsecret-node-startup-retry-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const blocker = createServer();
  await new Promise<void>((resolve) => blocker.listen(0, "127.0.0.1", resolve));
  const address = blocker.address();
  assert.ok(typeof address === "object" && address);
  await assert.rejects(
    () => startNodeServer({ dataDir: dir, port: address.port, env: {} }),
    /EADDRINUSE/,
  );
  await new Promise<void>((resolve, reject) =>
    blocker.close((error) => (error ? reject(error) : resolve())),
  );
  const retry = await startNodeServer({
    dataDir: dir,
    port: address.port,
    env: {},
  });
  await retry.close();
});

test("Node server recovers ownerless lock and abandoned recovery directories", async (t) => {
  const dir = await temporaryDir("agentsecret-node-lock-recovery-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const lock = join(dir, "server.lock");
  await mkdir(lock);
  await mkdir(lock + ".recovery");
  const stale = new Date(Date.now() - 5000);
  await utimes(lock, stale, stale);
  await utimes(lock + ".recovery", stale, stale);
  const server = await startNodeServer({ dataDir: dir, port: 0, env: {} });
  await server.close();
});

test("Node/SQLite server: registry migrations are idempotent across restarts", async (t) => {
  const dir = await temporaryDir("agentsecret-node-migrate-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const first = await startNodeServer({ dataDir: dir, port: 0, env: {} });
  const address = first.server.address();
  assert.ok(typeof address === "object" && address);
  await first.close();
  const second = await startNodeServer({
    dataDir: dir,
    port: address.port,
    env: {},
  });
  await second.close();
});

test("Node/SQLite server: unknown route returns the same shape as the Worker", async (t) => {
  const dir = await temporaryDir("agentsecret-node-routes-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const handle = await startNodeServer({
    dataDir: dir,
    port: 0,
    env: {},
  });
  t.after(() => handle.close());
  const address = handle.server.address();
  assert.ok(typeof address === "object" && address);
  const origin = "http://127.0.0.1:" + address.port;

  const health = await fetch(origin + "/health");
  assert.equal(health.status, 200);

  const missing = await fetch(origin + "/api/definitely-not-a-route");
  assert.equal(missing.status, 404);
  assert.equal((await missing.json()).error, "not_found");

  const unauthorized = await fetch(origin + "/api/user/policies");
  assert.ok([401, 403].includes(unauthorized.status));
});

test("Node HTTP adapter rejects oversized request bodies with a sanitized 413", async (t) => {
  const dir = await temporaryDir("agentsecret-node-body-limit-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const handle = await startNodeServer({ dataDir: dir, port: 0, env: {} });
  t.after(() => handle.close());
  const address = handle.server.address();
  assert.ok(typeof address === "object" && address);
  const response = await fetch(
    "http://127.0.0.1:" + address.port + "/api/user/profile",
    {
      method: "POST",
      body: "x".repeat(65 * 1024),
    },
  );
  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { error: "request_too_large" });
});

test("Node HTTP adapter replaces a client supplied connecting IP with its socket peer", () => {
  const headers = toHeaders({
    headers: { "cf-connecting-ip": "203.0.113.9", host: "localhost" },
    socket: { remoteAddress: "127.0.0.1" },
  } as Parameters<typeof toHeaders>[0]);
  assert.equal(headers.get("cf-connecting-ip"), "127.0.0.1");
});

test("Node HTTP adapter rejects authority-bearing request targets", async (t) => {
  const dir = await temporaryDir("agentsecret-node-target-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const publicOrigin = "https://public.example.test";
  const handle = await startNodeServer({
    dataDir: dir,
    port: 0,
    publicOrigin,
    env: {},
  });
  t.after(() => handle.close());
  const address = handle.server.address();
  assert.ok(typeof address === "object" && address);
  const accountId = "acct_request_target";
  const timestamp = Date.now();
  await handle.env.DB.prepare(
    "INSERT INTO accounts (id, status, name, email, avatar_url, version, created_at, updated_at) VALUES (?, 'active', ?, ?, '', 1, ?, ?)",
  )
    .bind(
      accountId,
      "Original Name",
      "target@example.test",
      timestamp,
      timestamp,
    )
    .run();
  const session = await signInSession(handle.env, publicOrigin, accountId);

  async function submit(path: string, origin: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const request = httpRequest(
        {
          host: "127.0.0.1",
          port: address.port,
          method: "POST",
          path,
          headers: {
            Cookie: "agentsecret_session=" + session,
            Origin: origin,
            "Content-Type": "application/json",
          },
        },
        (response) => {
          response.resume();
          response.once("end", () => resolve(response.statusCode ?? 0));
        },
      );
      request.once("error", reject);
      request.write(JSON.stringify({ name: "Attacker Name" }));
      request.end();
    });
  }

  assert.equal(
    await submit(
      "//evil.example.test/api/user/onboarding",
      "https://evil.example.test",
    ),
    400,
  );
  assert.equal(
    await submit(
      "/\\evil.example.test/api/user/onboarding",
      "https://evil.example.test",
    ),
    400,
  );
  assert.equal(
    await submit(
      "http://evil.example.test/api/user/onboarding",
      "https://evil.example.test",
    ),
    400,
  );
  assert.equal(
    await handle.env.DB.prepare(
      "SELECT display_name FROM account_onboarding WHERE account_id = ?",
    )
      .bind(accountId)
      .first(),
    null,
    "rejected authority-bearing targets must not mutate authenticated state",
  );
  assert.equal(
    await submit("/api/user/onboarding", publicOrigin),
    200,
    "a normal origin-relative target reaches the shared application handler",
  );
});

test("Node HTTP adapter applies one device-code limit across forged client IP headers", async (t) => {
  const dir = await temporaryDir("agentsecret-node-device-limit-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const portProbe = createServer();
  await new Promise<void>((resolve) =>
    portProbe.listen(0, "127.0.0.1", resolve),
  );
  const portAddress = portProbe.address();
  assert.ok(typeof portAddress === "object" && portAddress);
  await new Promise<void>((resolve, reject) =>
    portProbe.close((error) => (error ? reject(error) : resolve())),
  );
  const port = portAddress.port;
  const handle = await startNodeServer({
    dataDir: dir,
    port,
    host: "127.0.0.1",
    publicOrigin: "http://127.0.0.1:" + port,
    env: {},
  });
  t.after(() => handle.close());
  const address = handle.server.address();
  assert.ok(typeof address === "object" && address);
  const origin = "http://127.0.0.1:" + address.port;
  const pair = await generateKeyPair("ES256");
  const jwk = await exportJWK(pair.publicKey);
  const statuses: number[] = [];
  const responseBodies: string[] = [];
  for (let attempt = 0; attempt < 11; attempt += 1) {
    const proof = await new SignJWT({
      htm: "POST",
      htu: origin + "/oauth/device/code",
    })
      .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
      .setIssuedAt()
      .setJti("device-limit-" + attempt)
      .sign(pair.privateKey);
    const response = await fetch(origin + "/oauth/device/code", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "198.51.100." + (attempt + 1),
        DPoP: proof,
      },
      body: JSON.stringify({ client_id: "agentsecret-cli" }),
    });
    statuses.push(response.status);
    responseBodies.push(await response.text());
  }
  assert.deepEqual(
    statuses,
    [...Array<number>(10).fill(200), 429],
    JSON.stringify(responseBodies),
  );
});

test("Node/SQLite server: health reports the authority and registry are configured", async (t) => {
  const dir = await temporaryDir("agentsecret-node-health-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const handle = await startNodeServer({ dataDir: dir, port: 0, env: {} });
  t.after(() => handle.close());
  const address = handle.server.address();
  assert.ok(typeof address === "object" && address);
  const response = await fetch("http://127.0.0.1:" + address.port + "/health");
  const body = (await response.json()) as Record<string, unknown>;
  assert.equal(body.service, "agentsecret");
  assert.equal(body.configured, true);
  assert.equal(body.rawExport, false);
});

test("Node/SQLite registry: updateAccountProfile commits and returns the updated row", async (t) => {
  const raw = new DatabaseSync(":memory:");
  t.after(() => raw.close());
  const migrationsDir = fileURLToPath(
    new URL("../migrations/", import.meta.url),
  );
  applyRegistryMigrations(raw, migrationsDir);
  const db = new SqliteRegistryDatabase(raw);
  const timestamp = Date.now();
  raw
    .prepare(
      "INSERT INTO accounts (id, status, name, email, avatar_url, version, created_at, updated_at) VALUES (?, 'active', ?, ?, '', 1, ?, ?)",
    )
    .run("acct_profile", "Old Name", "old@example.com", timestamp, timestamp);

  const updated = await updateAccountProfile(db, "acct_profile", {
    name: "New Name",
  });
  assert.equal(updated.name, "New Name");
  assert.equal(updated.version, 2);

  const row = raw
    .prepare("SELECT name, version FROM accounts WHERE id = ?")
    .get("acct_profile") as { name: string; version: number } | undefined;
  assert.equal(row?.name, "New Name");
  assert.equal(row?.version, 2);
  const staged = raw
    .prepare("SELECT COUNT(*) AS count FROM pending_profile_updates")
    .get() as { count: number };
  assert.equal(staged.count, 0);
});

test("Node authority host retires handled alarms, retries failures and resumes persisted alarms", async (t) => {
  const dir = await temporaryDir("agentsecret-node-alarm-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const host = new NodeAuthorityHost({ dataDir: dir, env: {} as Env });
  t.after(() => host.close());
  const runtime = (host as unknown as AuthorityRuntimeProbe).runtime("default");

  // A successfully handled alarm with no replacement is retired durably.
  await runtime.storage.setAlarm(Date.now() - 1000);
  await waitFor(() => runtime.storage.alarmAt() === null);
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(runtime.storage.alarmAt(), null);

  // A failing alarm keeps its persisted instant so the host retries it.
  const original = runtime.kernel.alarm.bind(runtime.kernel);
  let calls = 0;
  runtime.kernel.alarm = async () => {
    calls += 1;
    if (calls === 1) throw new Error("synthetic_alarm_failure");
    return original();
  };
  await runtime.storage.setAlarm(Date.now() - 1000);
  await waitFor(() => calls >= 2 && runtime.storage.alarmAt() === null);
  runtime.kernel.alarm = original;

  // A persisted due alarm survives a restart and is fired and retired by the
  // resumed host. The row is written directly so the live host cannot fire it
  // before shutdown.
  runtime.db
    .prepare(
      "INSERT OR REPLACE INTO authority_alarm (id, alarm_at) VALUES (1, ?)",
    )
    .run(Date.now() - 1000);
  host.close();

  const resumed = new NodeAuthorityHost({ dataDir: dir, env: {} as Env });
  t.after(() => resumed.close());
  resumed.resume();
  const resumedRuntime = (resumed as unknown as AuthorityRuntimeProbe).runtime(
    "default",
  );
  await waitFor(() => resumedRuntime.storage.alarmAt() === null);
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(resumedRuntime.storage.alarmAt(), null);
});

test("Node HTTP adapter forwards every Set-Cookie through a real social callback", async (t) => {
  const dir = await temporaryDir("agentsecret-node-cookies-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const handle = await startNodeServer({
    dataDir: dir,
    port: 0,
    env: {
      GITHUB_OAUTH_CLIENT_ID: "test-client-id",
      GITHUB_OAUTH_CLIENT_SECRET: "test-client-secret",
    },
  });
  t.after(() => handle.close());
  const address = handle.server.address();
  assert.ok(typeof address === "object" && address);
  const origin = "http://127.0.0.1:" + address.port;

  const realFetch = globalThis.fetch;
  let beginTokenExchange!: () => void;
  let finishTokenExchange!: (response: Response) => void;
  const tokenExchangeStarted = new Promise<void>((resolve) => {
    beginTokenExchange = resolve;
  });
  const tokenExchange = new Promise<Response>((resolve) => {
    finishTokenExchange = resolve;
  });
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    if (url === "https://github.com/login/oauth/access_token") {
      beginTokenExchange();
      return tokenExchange;
    }
    if (url === "https://api.github.com/user") {
      return Response.json({
        id: 424242,
        login: "octocat",
        name: "Octo Cat",
        avatar_url: "https://avatars.githubusercontent.com/u/424242",
      });
    }
    if (url === "https://api.github.com/user/emails") {
      return Response.json([
        { email: "octocat@example.com", primary: true, verified: true },
      ]);
    }
    return realFetch(input, init);
  }) as typeof fetch;
  t.after(() => {
    globalThis.fetch = realFetch;
  });

  const start = await fetch(origin + "/auth/github", { redirect: "manual" });
  assert.equal(start.status, 302);
  const location = start.headers.get("Location");
  assert.ok(location);
  const state = new URL(location).searchParams.get("state");
  assert.ok(state);
  const transactionSetCookie = start.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith("agentsecret_oauth_github="));
  assert.ok(transactionSetCookie);
  const binding = transactionSetCookie
    .slice("agentsecret_oauth_github=".length)
    .split(";")[0]
    .trim();
  assert.ok(binding.length > 0);

  const callbackPromise = fetch(
    origin +
      "/auth/github/callback?code=fake-code&state=" +
      encodeURIComponent(state),
    {
      redirect: "manual",
      headers: { Cookie: "agentsecret_oauth_github=" + binding },
    },
  );
  await tokenExchangeStarted;
  let callbackSettled = false;
  const callbackObserved = callbackPromise.then((response) => {
    callbackSettled = true;
    return response;
  });
  const closing = handle.close();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(
    callbackSettled,
    false,
    "shutdown must wait for the provider callback",
  );
  finishTokenExchange(Response.json({ access_token: "gho_test_token" }));
  const callback = await callbackObserved;
  await closing;
  assert.equal(callback.status, 303);
  assert.equal(callback.headers.get("Location"), "/?view=dashboard");
  const cookies = callback.headers.getSetCookie();
  assert.equal(cookies.length, 2);
  assert.ok(
    cookies.some((cookie) => cookie.startsWith("agentsecret_session=")),
    "the session cookie must survive alongside the transaction expiry",
  );
  assert.ok(
    cookies.some(
      (cookie) =>
        cookie.startsWith("agentsecret_oauth_github=") &&
        cookie.includes("Max-Age=0"),
    ),
    "the transaction cookie must be expired, not dropped",
  );
});

test("Node server lock: synchronized startups with stale lock and recovery directories admit exactly one process", async (t) => {
  const dir = await temporaryDir("agentsecret-node-lock-race-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const lockDir = join(dir, "server.lock");
  const recoveryDir = lockDir + ".recovery";
  const staleOwner = JSON.stringify({ pid: 2_147_483_647, token: "stale" });
  const stale = new Date(Date.now() - 5000);
  for (const path of [lockDir, recoveryDir]) {
    await mkdir(path);
    await writeFile(join(path, "owner.json"), staleOwner);
    await utimes(path, stale, stale);
  }

  const root = fileURLToPath(new URL("..", import.meta.url));
  const lockModule = pathToFileURL(join(root, "src/server/lock.ts")).href;
  const script = [
    'import { acquireServerLock } from "' + lockModule + '";',
    'process.stdout.write("READY\\n");',
    'process.stdin.once("data", () => {',
    "  try {",
    "    acquireServerLock(" + JSON.stringify(dir) + ");",
    '    console.log("ACQUIRED:" + process.pid);',
    "    setInterval(() => {}, 1000);",
    "  } catch (error) {",
    '    console.log("FAILED:" + (error && error.message ? error.message : String(error)));',
    "    process.exit(1);",
    "  }",
    "});",
  ].join("\n");

  const children = Array.from({ length: 2 }, () =>
    spawn(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "-e", script],
      { cwd: root, stdio: ["pipe", "pipe", "pipe"] },
    ),
  );
  t.after(() => {
    for (const child of children) {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already exited.
      }
    }
  });

  const ready = new Set<number>();
  const results = new Map<number, string>();
  for (const child of children) {
    const pid = child.pid;
    assert.ok(pid);
    let buffer = "";
    const lines = createInterface({ input: child.stdout });
    lines.on("line", (line) => {
      if (line === "READY") ready.add(pid);
      else if (line.startsWith("ACQUIRED:") || line.startsWith("FAILED:"))
        results.set(pid, line);
    });
    child.stderr.resume();
  }

  await waitFor(() => ready.size === children.length);
  for (const child of children) child.stdin.write("GO\n");
  await waitFor(() => results.size === children.length);

  const outcomes = [...results.entries()];
  const acquired = outcomes.filter(([, result]) =>
    result.startsWith("ACQUIRED:"),
  );
  const failed = outcomes.filter(([, result]) => result.startsWith("FAILED:"));
  assert.equal(acquired.length, 1, JSON.stringify(outcomes));
  assert.equal(failed.length, 1, JSON.stringify(outcomes));
  assert.match(
    failed[0]?.[1] ?? "",
    /^FAILED:agentsecret server is already running for this data directory$/,
  );
  const acquiredPid = Number(acquired[0]?.[1].slice("ACQUIRED:".length));
  assert.equal(acquiredPid, acquired[0]?.[0]);
  assert.doesNotThrow(() => process.kill(acquiredPid, 0));
});
