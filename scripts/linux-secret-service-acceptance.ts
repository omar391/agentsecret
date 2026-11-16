import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { exportJWK } from "jose";

async function main() {
  if (process.platform !== "linux")
    throw new Error("This acceptance command requires Linux.");

  const directory = mkdtempSync(
    path.join(tmpdir(), "agentsecret-secret-service-acceptance-"),
  );
  chmodSync(directory, 0o700);
  const previousConfigDirectory = process.env.AGENTSECRET_CONFIG_DIR;
  process.env.AGENTSECRET_CONFIG_DIR = directory;

  let saved = false;
  try {
    const [{ createSigningPair, restoreSigningPair }, store] =
      await Promise.all([import("../cli/keys"), import("../cli/store")]);
    const pair = await createSigningPair();
    const privateJwk = await exportJWK(pair.privateKey);
    const server = `https://secret-service-acceptance-${randomUUID()}.invalid`;

    store.save(
      {
        server,
        accessToken: "synthetic-secret-service-acceptance-token",
        expiresAt: Date.now() + 60_000,
        tenant: "synthetic-secret-service-acceptance",
      },
      privateJwk,
    );
    saved = true;

    const profile = store.load();
    assert.equal(profile?.server, server);
    assert.deepEqual(store.privateKey(server), privateJwk);

    const restored = await restoreSigningPair(store.privateKey(server));
    const challenge = crypto.getRandomValues(new Uint8Array(48));
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      restored.privateKey,
      challenge,
    );
    assert.equal(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        restored.publicKey,
        signature,
        challenge,
      ),
      true,
    );

    store.clear();
    saved = false;
    assert.equal(store.load(), null);
    assert.throws(() => store.privateKey(server));
    const osRelease = readFileSync("/etc/os-release", "utf8");
    const osName = /^PRETTY_NAME="?([^\r\n"]+)/m.exec(osRelease)?.[1];
    const keyringVersion = execFileSync(
      "dpkg-query",
      ["-W", "-f=${Version}", "gnome-keyring"],
      { encoding: "utf8" },
    ).trim();
    console.log(
      `Linux Secret Service acceptance passed (${osName || "Linux"}; Node ${process.version}; ${process.arch}; gnome-keyring ${keyringVersion}): synthetic signing key restored, used, and removed.`,
    );
  } finally {
    const store = await import("../cli/store");
    if (saved) store.clear();
    rmSync(directory, { recursive: true, force: true });
    if (previousConfigDirectory === undefined)
      delete process.env.AGENTSECRET_CONFIG_DIR;
    else process.env.AGENTSECRET_CONFIG_DIR = previousConfigDirectory;
  }
}

main().catch(() => {
  console.error(
    "Linux Secret Service acceptance failed; no provider account was accessed.",
  );
  process.exitCode = 1;
});
