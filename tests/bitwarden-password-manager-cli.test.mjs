import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";

const root = new URL("../", import.meta.url).pathname;

for (const [configuration, serverUrl, statusServerUrl] of [
  [
    "explicit server",
    "https://vault.bitwarden.com",
    "https://vault.bitwarden.com",
  ],
  ["default server", "https://bitwarden.com", null],
]) {
  test(`hosted CLI uses the protected local Bitwarden wrapper with ${configuration} without a shared-daemon dependency`, async (t) => {
    const folderRoot = path.join(root, "tmp");
    await mkdir(folderRoot, { recursive: true });
    const folder = await mkdtemp(path.join(folderRoot, "bwp-companion-"));
    t.after(() => rm(folder, { recursive: true, force: true }));

    const server = "https://broker.example.test";
    const tenant = "tenant-synthetic-bwpm";
    const connectionId = "connection-synthetic-bwpm-1";
    const connectionRevision = 3;
    const providerMode = "bitwarden-password-manager";
    const profile = {
      schema: "agentsecret/fastflow-bitwarden-profile/v1",
      appName: "agentsecret-test-profile",
      userId: "synthetic-bwpm-user",
      userEmail: "bwpm@example.invalid",
      serverUrl,
    };
    const binding = {
      server,
      tenant,
      connectionId,
      connectionRevision,
      providerMode,
    };
    const key = createHash("sha256")
      .update(JSON.stringify(binding))
      .digest("base64url");
    const itemId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const reference = `${itemId}#/login/password`;
    const secretValue = "synthetic-bwpm-secret-value";
    const providerRecord = {
      schema: "agentsecret/provider-credential/v2",
      binding,
      credential: JSON.stringify(profile),
    };
    const preload = path.join(folder, "bwp-preload.mjs");
    await writeFile(
      preload,
      `import child from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
Object.defineProperty(process, 'platform', { value: 'darwin' });
const storage = new Map();
const binding = ${JSON.stringify(binding)};
const key = createHash('sha256').update(JSON.stringify(binding)).digest('base64url');
storage.set('AgentSecret-provider-v2:' + key, Buffer.from(${JSON.stringify(JSON.stringify(providerRecord))}).toString('base64url'));
const itemId = ${JSON.stringify(itemId)};
const secretValue = ${JSON.stringify(secretValue)};
let providerSynced = false;
child.execFileSync = (command, args, options = {}) => {
  if (command === '/usr/bin/security') {
    if (args[0] === '-i') {
      const match = String(options.input || '').match(/-a "([^"]+)" -s "([^"]+)" -w "([^"]+)"/);
      if (!match) throw new Error('invalid synthetic Keychain write');
      storage.set(match[2] + ':' + match[1], match[3]);
      return '';
    }
    if (args[0] === 'find-generic-password') {
      const account = args[args.indexOf('-a') + 1];
      const service = args[args.indexOf('-s') + 1];
      const value = storage.get(service + ':' + account);
      if (value === undefined) {
        const error = new Error('missing synthetic Keychain item');
        error.status = 44;
        throw error;
      }
      return value + '\\n';
    }
    if (args[0] === 'delete-generic-password') {
      const account = args[args.indexOf('-a') + 1];
      const service = args[args.indexOf('-s') + 1];
      storage.delete(service + ':' + account);
      return '';
    }
  }
  if (command.endsWith('/fastflow')) {
    throw new Error('shared daemon has an incompatible CLI; local wrapper is independently audited');
  }
  if (command.endsWith('/fastflow-bw')) {
    if (options.env.FASTFLOW_APP_NAME !== ${JSON.stringify(profile.appName)}) throw new Error('wrong Fastflow profile');
    if (args.join(' ') === '--raw status') return JSON.stringify({ serverUrl: ${JSON.stringify(statusServerUrl)}, userEmail: ${JSON.stringify(profile.userEmail)}, userId: ${JSON.stringify(profile.userId)}, status: 'unlocked' });
    if (args.join(' ') === '--raw sync') {
      if (process.env.BWP_TEST_SYNC_FAIL === '1') throw new Error('synthetic provider sync unavailable');
      providerSynced = true;
      return 'Syncing complete.';
    }
    if (args.join(' ') === '--raw get item ' + itemId) {
      if (process.env.BWP_TEST_SYNC_FAIL === '1') process.stderr.write('stale-cache-read-attempted');
      if (!providerSynced) throw new Error('provider freshness was not established');
      return JSON.stringify({ id: itemId, type: 1, login: { password: secretValue }, fields: [] });
    }
    throw new Error('unexpected synthetic Bitwarden invocation');
  }
  throw new Error('unexpected process invocation');
};
syncBuiltinESMExports();
globalThis.fetch = async (url, options = {}) => {
  const parsed = new URL(String(url));
  if (parsed.pathname === '/oauth/token/oidc') {
    return new Response(JSON.stringify({ access_token: 'as2.' + Buffer.from(${JSON.stringify(tenant)}).toString('base64url') + '.synthetic', expires_in: 900 }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  if (parsed.pathname === '/mcp') {
    const request = JSON.parse(options.body);
    if (request.params.name === 'secrets_find') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { isError: true, content: [{ type: 'text', text: 'secret_store_unavailable' }] } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (request.params.name === 'list_available_secrets') {
      const entry = { alias: 'BWPM_TEST', description: 'synthetic fixture', allowedDomains: ['api.github.com'], allowedMethods: ['GET'], credential_sink: { type: 'bearer' }, connection_status: 'ready', provider_mode: 'bitwarden-password-manager', provider_capabilities: { status: 'requires-companion', read: true, create: false, update: false, conditional_update: false, verify_after_write: false, delete: false, reason: 'An owner-bound Fastflow local companion reads exact Bitwarden item fields after cloud authorization. Decrypted item JSON and values stay in process. Create/update/delete are not enabled, and the cloud has no BWP adapter.' }, companion_binding: { connection_id: ${JSON.stringify(connectionId)}, connection_revision: ${connectionRevision} } };
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ available_secrets: [entry] }) }] } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
  }
  throw new Error('unexpected synthetic request');
};
`,
    );
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        preload,
        path.join(root, "dist/cli.mjs"),
        "secrets",
        "find",
        "--server",
        server,
        "--alias",
        "BWPM_TEST",
        "--reference",
        reference,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          AGENTSECRET_SERVER: server,
          AGENTSECRET_OIDC_TOKEN: "synthetic-assertion",
        },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      status: "available",
      provider: "bitwarden-password-manager",
      reference,
    });
    assert.doesNotMatch(
      result.stdout + result.stderr,
      /synthetic-bwpm-secret-value|bwpm@example\.invalid|synthetic-bwpm-user/,
    );

    const offline = spawnSync(
      process.execPath,
      [
        "--import",
        preload,
        path.join(root, "dist/cli.mjs"),
        "secrets",
        "find",
        "--server",
        server,
        "--alias",
        "BWPM_TEST",
        "--reference",
        reference,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          AGENTSECRET_SERVER: server,
          AGENTSECRET_OIDC_TOKEN: "synthetic-assertion",
          BWP_TEST_SYNC_FAIL: "1",
        },
      },
    );
    assert.notEqual(offline.status, 0);
    assert.doesNotMatch(
      offline.stdout + offline.stderr,
      /stale-cache-read-attempted|synthetic-bwpm-secret-value|bwpm@example\.invalid|synthetic-bwpm-user/,
    );

    const request = {
      jsonrpc: "2.0",
      id: 17,
      method: "tools/call",
      params: {
        name: "secrets_find",
        arguments: { secret_alias: "BWPM_TEST", reference },
      },
    };
    const mcp = spawnSync(
      process.execPath,
      [
        "--import",
        preload,
        path.join(root, "dist/cli.mjs"),
        "mcp",
        "--server",
        server,
      ],
      {
        encoding: "utf8",
        input: JSON.stringify(request) + "\n",
        env: {
          ...process.env,
          AGENTSECRET_SERVER: server,
          AGENTSECRET_OIDC_TOKEN: "synthetic-assertion",
        },
      },
    );
    assert.equal(mcp.status, 0, mcp.stderr);
    assert.deepEqual(JSON.parse(mcp.stdout), {
      jsonrpc: "2.0",
      id: 17,
      result: {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              status: "available",
              provider: "bitwarden-password-manager",
              reference,
            }),
          },
        ],
      },
    });
    assert.doesNotMatch(
      mcp.stdout + mcp.stderr,
      /synthetic-bwpm-secret-value|bwpm@example\.invalid|synthetic-bwpm-user/,
    );
  });
}
