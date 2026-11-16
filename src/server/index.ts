import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import type { Server } from "node:http";
import type { Env } from "../types";
import type { HostAdapters } from "../core/application";
import { NodeAuthorityHost } from "./authority-host";
import { NodeAssetsAdapter } from "./assets";
import { createNodeServer } from "./http";
import { acquireServerLock } from "./lock";
import { applyRegistryMigrations, SqliteRegistryDatabase } from "./registry";

export interface NodeServerOptions {
  dataDir?: string;
  port?: number;
  host?: string;
  publicOrigin?: string;
  assetsDir?: string;
  /** Extra environment bindings (secrets, feature flags) for this deployment. */
  env?: Record<string, unknown>;
}

export interface NodeServerHandle {
  server: Server;
  env: Env;
  authorityHost: NodeAuthorityHost;
  close(): Promise<void>;
}

/** Environment variables forwarded from the process into the server Env. */
const FORWARDED_ENV = [
  "TENANTS",
  "PUBLIC_ORIGIN",
  "MONTHLY_ALLOWANCE",
  "VAULT_KEYS",
  "VAULT_ACTIVE_KEY",
  "OAUTH_CLIENTS",
  "WORKLOAD_TRUST",
  "MCP_AUTH_TOKEN",
  "GITHUB_OAUTH_CLIENT_ID",
  "GITHUB_OAUTH_CLIENT_SECRET",
  "GOOGLE_OIDC_CLIENT_ID",
  "GOOGLE_OIDC_CLIENT_SECRET",
  "ONEPASSWORD_SERVICE_ACCOUNT_WRITES",
  "AGENTSECRET_COMPANION_WRITES",
  "SECRET_SAVE_TEST_CLOCK",
] as const;

function pickEnv(source: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of FORWARDED_ENV) {
    const value = source[key];
    if (value !== undefined) out[key] = value;
  }
  return out;
}

/**
 * Start the self-hosted Node server.
 *
 * One process owns one data directory: a SQLite transaction lock rejects a
 * second process,
 * the account/identity registry lives in `registry.db` (repository
 * migrations applied once), and each tenant authority lives in its own
 * SQLite file under `authority/`. Scheduled recovery alarms are durable and
 * resume on start. The same `handleApplicationRequest` the Cloudflare Worker
 * uses serves every request, so the two deployments enforce identical rules.
 */
export async function startNodeServer(
  options: NodeServerOptions = {},
): Promise<NodeServerHandle> {
  const dataDir = resolve(
    options.dataDir ?? process.env.AGENTSECRET_DATA_DIR ?? "./data",
  );
  const port =
    options.port ??
    Number(process.env.AGENTSECRET_PORT ?? process.env.PORT ?? 8787);
  const host = options.host ?? process.env.AGENTSECRET_HOST ?? "127.0.0.1";
  const publicOrigin =
    options.publicOrigin ??
    process.env.PUBLIC_ORIGIN ??
    "http://" + host + ":" + port;
  const assetsDir = resolve(
    options.assetsDir ??
      process.env.AGENTSECRET_ASSETS_DIR ??
      fileURLToPath(new URL("../../web/dist/", import.meta.url)),
  );
  const migrationsDir = fileURLToPath(
    new URL("../../migrations/", import.meta.url),
  );

  const releaseLock = acquireServerLock(dataDir);
  let registryDb: DatabaseSync | undefined;
  let authorityHost: NodeAuthorityHost | undefined;
  let server: Server | undefined;
  try {
    mkdirSync(dataDir, { recursive: true });

    // Account/identity registry (the Turso/D1 counterpart) in one SQLite file.
    registryDb = new DatabaseSync(join(dataDir, "registry.db"));
    applyRegistryMigrations(registryDb, migrationsDir);
    const registry = new SqliteRegistryDatabase(registryDb);

    const env = {
      ...pickEnv(process.env),
      ...(options.env ?? {}),
      DB: registry,
      PUBLIC_ORIGIN: publicOrigin,
    } as unknown as Env;

    authorityHost = new NodeAuthorityHost({ dataDir, env });
    // The in-process authority stands in for the SECURITY Durable Object
    // namespace, so the shared authority() routing gate dispatches locally.
    env.SECURITY = authorityHost.namespace() as unknown as Env["SECURITY"];

    // Resume durable scheduled recovery before accepting traffic.
    authorityHost.resume();

    const adapters: HostAdapters = {
      assets: new NodeAssetsAdapter(assetsDir),
      background: {
        waitUntil: (promise) => {
          promise.catch(() => {});
        },
      },
      alarms: {
        available: () => false,
        async setAlarm(): Promise<void> {
          throw new Error("alarms_require_authority_scheduling");
        },
      },
      authority: {
        available: () => true,
        dispatch: (tenant, command) => authorityHost!.dispatch(tenant, command),
      },
    };

    const listeningServer = createNodeServer({ env, adapters, publicOrigin });
    server = listeningServer;
    await new Promise<void>((resolveListen, rejectListen) => {
      listeningServer.once("error", rejectListen);
      listeningServer.listen(port, host, () => resolveListen());
    });

    let closed = false;
    const close = async (): Promise<void> => {
      if (closed) return;
      closed = true;
      await new Promise<void>((done) => listeningServer.close(() => done()));
      authorityHost!.close();
      try {
        registryDb!.close();
      } catch {
        // Best-effort.
      }
      releaseLock();
    };

    return { server: listeningServer, env, authorityHost, close };
  } catch (error) {
    if (server?.listening)
      await new Promise<void>((done) => server!.close(() => done()));
    authorityHost?.close();
    try {
      registryDb?.close();
    } catch {
      /* Best-effort startup unwind. */
    }
    releaseLock();
    throw error;
  }
}

/** CLI entry: `npm run serve` (or `node dist/server.mjs`). */
export async function main(): Promise<void> {
  const handle = await startNodeServer();
  const address = handle.server.address();
  const port = typeof address === "object" && address ? address.port : 8787;
  console.log("agentsecret listening on http://127.0.0.1:" + port);
  const shutdown = () => {
    void handle.close().then(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

const invokedAsScript =
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invokedAsScript) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
