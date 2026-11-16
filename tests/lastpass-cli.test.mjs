import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const root = new URL("../", import.meta.url).pathname;

const hostPlatform = process.platform;
Object.defineProperty(process, "platform", {
  configurable: true,
  get() {
    return "darwin";
  },
  set() {},
});

test("LastPass hosted CLI and stdio MCP read only the exact cloud-authorized companion ref", async (t) => {
  const work = await mkdtemp(path.join(root, "tmp/lastpass-companion-"));
  t.after(() => rm(work, { recursive: true, force: true }));
  const profileRoot = path.join(
    homedir(),
    ".local",
    "share",
    "agentsecret",
    "lastpass",
  );
  await mkdir(profileRoot, { recursive: true, mode: 0o700 });
  const profileHome = await mkdtemp(path.join(profileRoot, "acceptance-"));
  await chmod(profileHome, 0o700);
  t.after(() => rm(profileHome, { recursive: true, force: true }));

  const server = "https://broker.example.test";
  const tenant = "tenant-synthetic-lastpass";
  const connectionId = "connection-synthetic-lastpass-1";
  const connectionRevision = 2;
  const binding = {
    server,
    tenant,
    connectionId,
    connectionRevision,
    providerMode: "lastpass",
  };
  const key = createHash("sha256")
    .update(JSON.stringify(binding))
    .digest("base64url");
  const itemId = "1234567890123456789";
  const reference = `${itemId}#/password`;
  const secretValue = "synthetic-lastpass-secret-value";
  const profile = {
    schema: "agentsecret/lastpass-profile/v1",
    home: profileHome,
    userEmail: "isolated@example.invalid",
  };
  const providerRecord = {
    schema: "agentsecret/provider-credential/v2",
    binding,
    credential: JSON.stringify(profile),
  };
  const preload = path.join(work, "lastpass-preload.mjs");
  await writeFile(
    preload,
    `import child from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { createHash } from 'node:crypto';
const storage = new Map();
const binding = ${JSON.stringify(binding)};
const key = createHash('sha256').update(JSON.stringify(binding)).digest('base64url');
const record = ${JSON.stringify(providerRecord)};
storage.set('AgentSecret-provider-v2:' + key, Buffer.from(JSON.stringify(record)).toString('base64url'));
const itemId = ${JSON.stringify(itemId)};
const secretValue = ${JSON.stringify(secretValue)};
const profileHome = ${JSON.stringify(profileHome)};
child.execFileSync = (command, args, options = {}) => {
  if (command === '/usr/bin/security') {
    if (args[0] === 'find-generic-password') {
      const account = args[args.indexOf('-a') + 1];
      const service = args[args.indexOf('-s') + 1];
      const value = storage.get(service + ':' + account);
      if (value === undefined) { const error = new Error('missing synthetic Keychain item'); error.status = 44; throw error; }
      return value + '\\n';
    }
  }
  if (command === 'lpass') {
    if (options.env.LPASS_HOME !== profileHome) throw new Error('wrong LastPass profile');
    if (args.join(' ') === 'status --color=never') return 'Logged in as isolated@example.invalid.\\n';
    if (args.join(' ') === 'show --json --sync=now --color=never ' + itemId) {
      return JSON.stringify([{ id: itemId, username: 'synthetic-user', password: secretValue, note: 'synthetic note' }]);
    }
    throw new Error('unexpected synthetic LastPass invocation');
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
      const entry = { alias: 'LP_TEST', description: 'synthetic fixture', allowedDomains: ['api.github.com'], allowedMethods: ['GET'], credential_sink: { type: 'bearer' }, connection_status: 'ready', provider_mode: 'lastpass', provider_capabilities: { status: 'requires-companion', read: true, create: false, update: false, conditional_update: false, verify_after_write: false, delete: false, reason: 'synthetic companion fixture' }, companion_binding: { connection_id: ${JSON.stringify(connectionId)}, connection_revision: ${connectionRevision} } };
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: { content: [{ type: 'text', text: JSON.stringify({ available_secrets: [entry] }) }] } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
  }
  throw new Error('unexpected synthetic request');
};
`,
  );
  const environment = {
    ...process.env,
    AGENTSECRET_SERVER: server,
    AGENTSECRET_OIDC_TOKEN: "synthetic-assertion",
  };
  const cli = spawnSync(
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
      "LP_TEST",
      "--reference",
      reference,
    ],
    { encoding: "utf8", env: environment },
  );
  assert.equal(cli.status, 0, cli.stderr);
  assert.deepEqual(JSON.parse(cli.stdout), {
    status: "available",
    provider: "lastpass",
    reference,
  });
  assert.doesNotMatch(
    cli.stdout + cli.stderr,
    /synthetic-lastpass-secret-value|isolated@example\.invalid|synthetic-user/,
  );

  const request = {
    jsonrpc: "2.0",
    id: 19,
    method: "tools/call",
    params: {
      name: "secrets_find",
      arguments: { secret_alias: "LP_TEST", reference },
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
      env: environment,
    },
  );
  assert.equal(mcp.status, 0, mcp.stderr);
  assert.deepEqual(JSON.parse(mcp.stdout), {
    jsonrpc: "2.0",
    id: 19,
    result: {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: "available",
            provider: "lastpass",
            reference,
          }),
        },
      ],
    },
  });
  assert.doesNotMatch(
    mcp.stdout + mcp.stderr,
    /synthetic-lastpass-secret-value|isolated@example\.invalid|synthetic-user/,
  );
});
