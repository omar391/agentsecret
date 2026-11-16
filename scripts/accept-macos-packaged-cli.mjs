import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import {
  mkdtemp,
  chmod,
  mkdir,
  rm,
  readFile,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function signalProcessGroup(child, signal) {
  if (!child.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== "ESRCH") child.kill(signal);
  }
}

function run(executable, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      ...options,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
    let forceTimer;
    const timer = setTimeout(() => {
      signalProcessGroup(child, "SIGTERM");
      forceTimer = setTimeout(
        () => signalProcessGroup(child, "SIGKILL"),
        5_000,
      );
      forceTimer.unref();
    }, 30_000);
    timer.unref();
    child.once("error", (error) => {
      clearTimeout(timer);
      clearTimeout(forceTimer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      clearTimeout(forceTimer);
      resolve({ code, signal, stdout, stderr });
    });
  });
}

function keychainEntryExists(server) {
  const account = Buffer.from(server).toString("base64url");
  const result = spawnSync(
    "/usr/bin/security",
    ["find-generic-password", "-a", account, "-s", "AgentSecret-v3"],
    {
      encoding: "utf8",
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 5_000,
      killSignal: "SIGKILL",
    },
  );
  if (result.status === 0) return true;
  if (
    result.status === 44 &&
    result.stderr.includes("The specified item could not be found")
  )
    return false;
  throw new Error(
    "Unable to check whether the Keychain profile already exists.",
  );
}

function closeServer(server) {
  return new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}

function deleteKeychainEntry(server) {
  const account = Buffer.from(server).toString("base64url");
  const result = spawnSync(
    "/usr/bin/security",
    ["delete-generic-password", "-a", account, "-s", "AgentSecret-v3"],
    {
      encoding: "utf8",
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 5_000,
      killSignal: "SIGKILL",
    },
  );
  if (result.status === 0) return;
  if (
    result.status === 44 &&
    result.stderr.includes("The specified item could not be found")
  )
    return;
  throw new Error("Unable to remove the synthetic Keychain entry.");
}

async function main() {
  if (process.platform !== "darwin")
    throw new Error("This acceptance command requires macOS.");

  const built = spawnSync("npm", ["run", "build:cli"], {
    cwd: root,
    encoding: "utf8",
    timeout: 60_000,
    killSignal: "SIGKILL",
  });
  assert.equal(built.status, 0, built.stdout + built.stderr);
  const { fixture } = await import("../tests/helpers.mjs");

  const workspace = await mkdtemp(
    path.join(tmpdir(), "agentsecret-packaged-keychain-"),
  );
  const config = path.join(workspace, "profile");
  await mkdir(config, { mode: 0o700 });
  await chmod(config, 0o700);
  let f;
  let edge;
  let base;
  let server;
  let executable;
  const candidateServers = [];
  let keychainProfileWasAbsent = false;
  let login;
  let loginClosed;
  let loginFinished = false;
  let loginStarted = false;
  let cleanupFailure;
  let preserveWorkspace = false;
  try {
    const occupiedServers = [];
    for (let attempt = 0; attempt < 8 && !server; attempt++) {
      let candidateBase;
      const candidate = createServer(async (req, res) => {
        try {
          const chunks = [];
          for await (const chunk of req) chunks.push(chunk);
          const response = await edge.fetch(candidateBase + req.url, {
            method: req.method,
            headers: req.headers,
            ...(req.method === "GET" || req.method === "HEAD"
              ? {}
              : { body: Buffer.concat(chunks) }),
          });
          res.writeHead(response.status, Object.fromEntries(response.headers));
          res.end(Buffer.from(await response.arrayBuffer()));
        } catch {
          res.writeHead(500);
          res.end();
        }
      });
      candidateServers.push(candidate);
      await new Promise((resolve, reject) => {
        candidate.once("error", reject);
        candidate.listen(0, "127.0.0.1", resolve);
      });
      candidateBase = `http://127.0.0.1:${candidate.address().port}`;
      if (keychainEntryExists(candidateBase)) {
        occupiedServers.push(candidate);
        continue;
      }
      server = candidate;
      base = candidateBase;
      keychainProfileWasAbsent = true;
    }
    await Promise.all(occupiedServers.map(closeServer));
    if (!server) throw new Error("Could not find an unused Keychain profile.");
    const keychainAccount = Buffer.from(base).toString("base64url");
    await writeFile(
      path.join(config, "keychain-recovery.json"),
      JSON.stringify({ server: base, account: keychainAccount }),
      { mode: 0o600, flag: "wx" },
    );
    f = await fixture({ bindings: { PUBLIC_ORIGIN: base } });
    edge = f.a;

    const connection = await f.admin("/api/user/vault-connections", {
      alias: "synthetic-packaged-keychain",
      config: {
        type: "onepassword-connect",
        accessToken: "synthetic-keychain-acceptance-token",
        apiUrl: "https://connect.1password.com",
        vaultId: "aaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
    });
    assert.equal(connection.status, 200, await connection.clone().text());
    const policy = await f.admin("/api/user/policies", {
      alias: "KEYCHAIN_ACCEPTANCE",
      description: "synthetic packaged macOS keychain acceptance",
      allowedDomains: ["api.github.com"],
      allowedMethods: ["GET"],
      injectionType: "bearer",
      connectionId: (await connection.json()).connection.id,
      secretId: "synthetic-item#synthetic-field",
    });
    assert.equal(policy.status, 200, await policy.clone().text());

    const packed = spawnSync(
      "npm",
      ["pack", "--json", "--pack-destination", workspace],
      {
        cwd: root,
        encoding: "utf8",
        timeout: 60_000,
        killSignal: "SIGKILL",
      },
    );
    assert.equal(packed.status, 0, packed.stderr);
    const artifact = JSON.parse(packed.stdout)[0];
    assert.ok(artifact.files.some((file) => file.path === "dist/cli.mjs"));
    const extracted = spawnSync(
      "tar",
      ["-xzf", path.join(workspace, artifact.filename), "-C", workspace],
      { encoding: "utf8" },
    );
    assert.equal(extracted.status, 0, extracted.stderr);
    executable = path.join(workspace, "package", "bin", "agentsecret.js");

    login = spawn(
      process.execPath,
      [
        executable,
        "login",
        "--server",
        base,
        "--device",
        "--aliases",
        "KEYCHAIN_ACCEPTANCE",
      ],
      {
        cwd: path.dirname(executable),
        env: { ...process.env, AGENTSECRET_CONFIG_DIR: config },
        detached: true,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    loginStarted = true;
    let loginStdout = "";
    let loginStderr = "";
    login.stdout
      .setEncoding("utf8")
      .on("data", (chunk) => (loginStdout += chunk));
    login.stderr
      .setEncoding("utf8")
      .on("data", (chunk) => (loginStderr += chunk));
    loginClosed = new Promise((resolve, reject) => {
      let forceTimer;
      const timer = setTimeout(() => {
        signalProcessGroup(login, "SIGTERM");
        forceTimer = setTimeout(
          () => signalProcessGroup(login, "SIGKILL"),
          5_000,
        );
        forceTimer.unref();
      }, 30_000);
      timer.unref();
      login.once("error", (error) => {
        clearTimeout(timer);
        clearTimeout(forceTimer);
        reject(error);
      });
      login.once("close", (code, signal) => {
        clearTimeout(timer);
        clearTimeout(forceTimer);
        loginFinished = true;
        resolve({ code, signal });
      });
    });

    const userCode = await new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("Device code was not displayed.")),
        10_000,
      );
      const inspect = () => {
        const match = loginStderr.match(
          /Confirm code:\s*([A-Z0-9_-]{12})(?:\s|$)/,
        );
        if (match) {
          clearTimeout(timer);
          resolve(match[1]);
        }
      };
      login.stderr.on("data", inspect);
      login.once("close", (code) => {
        if (code !== 0) {
          clearTimeout(timer);
          reject(
            new Error("Packaged login failed before approval: " + loginStderr),
          );
        }
      });
      inspect();
    });
    const approved = await f.approveDevice(
      userCode,
      null,
      "KEYCHAIN_ACCEPTANCE",
    );
    assert.equal(approved.status, 200, await approved.clone().text());
    const closed = await loginClosed;
    assert.deepEqual(closed, { code: 0, signal: null }, loginStderr);
    assert.match(loginStdout + loginStderr, /Authenticated/);

    const status = await run(
      process.execPath,
      [executable, "status", "--remote"],
      {
        cwd: path.dirname(executable),
        env: { ...process.env, AGENTSECRET_CONFIG_DIR: config },
      },
    );
    assert.equal(status.code, 0, status.stderr);
    const statusResult = JSON.parse(status.stdout);
    assert.equal(statusResult.status, "stored");
    assert.equal(statusResult.remoteVerification, "authenticated");

    const logout = await run(
      process.execPath,
      [executable, "logout", "--remote"],
      {
        cwd: path.dirname(executable),
        env: { ...process.env, AGENTSECRET_CONFIG_DIR: config },
      },
    );
    assert.equal(logout.code, 0, logout.stderr);
    assert.deepEqual(JSON.parse(logout.stdout), {
      status: "logged_out",
      remoteRevocation: "revoked",
      localSession: "cleared",
    });
    assert.equal(
      await readFile(path.join(config, "session.json")).catch(() => null),
      null,
    );
    console.log(
      "Packaged macOS CLI acceptance passed: synthetic device enrollment, real Keychain-backed DPoP status, and remote logout/key removal.",
    );
  } finally {
    if (login && !loginFinished) {
      signalProcessGroup(login, "SIGTERM");
      await Promise.race([
        loginClosed?.catch((error) => (cleanupFailure = error)),
        new Promise((resolve) => setTimeout(resolve, 5_000)),
      ]);
      if (!loginFinished) signalProcessGroup(login, "SIGKILL");
      await loginClosed?.catch((error) => (cleanupFailure = error));
    }
    if (loginStarted && executable) {
      await run(process.execPath, [executable, "logout"], {
        cwd: path.dirname(executable),
        env: { ...process.env, AGENTSECRET_CONFIG_DIR: config },
      }).catch(() => null);
    }
    if (keychainProfileWasAbsent && base) {
      try {
        if (keychainEntryExists(base)) deleteKeychainEntry(base);
        if (keychainEntryExists(base))
          throw new Error("The synthetic Keychain entry is still present.");
      } catch (error) {
        cleanupFailure ||= error;
      }
    }
    const closedServers = await Promise.allSettled(
      candidateServers
        .filter((candidate) => candidate.listening)
        .map(closeServer),
    );
    if (closedServers.some((result) => result.status === "rejected"))
      cleanupFailure ||= new Error(
        "A temporary acceptance listener did not close.",
      );
    if (f) await f.dispose();
    if (cleanupFailure) {
      preserveWorkspace = true;
      console.error(
        `Cleanup did not confirm Keychain removal. Recovery profile retained at ${workspace}`,
      );
    }
    if (!preserveWorkspace)
      await rm(workspace, { recursive: true, force: true });
    if (cleanupFailure)
      throw new Error(`Acceptance cleanup failed; retained ${workspace}.`);
  }
}

main().catch((error) => {
  console.error(
    "Packaged macOS CLI acceptance failed; it used only a synthetic Worker identity and no provider account.",
  );
  if (error instanceof Error) console.error(error.message);
  process.exitCode = 1;
});
