# AgentSecret

AgentSecret is a policy-bound secret broker for AI agents and developer tooling.
An agent never receives a raw provider credential. Instead it asks the broker to
perform an approved operation; the broker resolves the credential inside a
trusted boundary, enforces the owner's policy, injects the secret into an
allowlisted request, and returns a bounded, scrubbed result. Provider secrets
stay reference-only to the agent.

This repository is the self-hostable product: a platform-neutral core, a Node
HTTP server with durable local SQLite storage, the React dashboard, the
standalone CLI and MCP companion, provider integrations, protocol utilities
and the Rust execution supervisor.

## Architecture

The same `handleApplicationRequest` core serves every deployment. A host
supplies a small set of explicit adapters — registry storage, account
authority, transactional storage, alarms, background work, assets and outbound
transport — so the product rules exist exactly once. The public Node server
implements those adapters over `node:http` and `node:sqlite`; a private
Cloudflare Worker wrapper supplies the same core over Durable Objects and Turso
(that wrapper is not part of this public repository).

Agent sessions authenticate with DPoP (Demonstrating Proof of Possession)
bound to the exact method and URL, and every account's authority state is
isolated per tenant. Results are reference-only: secret values are never
returned to the caller, only bounded metadata and scrubbed upstream responses.

## Self-hosting

Requires Node.js 22 or newer.

```sh
npm ci
npm --prefix web ci
npm run build
```

Configure the deployment through environment variables and run the Node server:

```sh
export AGENTSECRET_DATA_DIR=./data
export PUBLIC_ORIGIN=http://localhost:8787
export VAULT_KEYS='{"v1":"<base64 32-byte key>"}'
export VAULT_ACTIVE_KEY=v1
# Provider credentials, for example:
export GITHUB_OAUTH_CLIENT_ID=...
export GITHUB_OAUTH_CLIENT_SECRET=...
export GOOGLE_OIDC_CLIENT_ID=...
export GOOGLE_OIDC_CLIENT_SECRET=...
npm run serve
```

`npm run serve` starts the dashboard and API on `AGENTSECRET_PORT` (default 8787) under `AGENTSECRET_DATA_DIR`. A SQLite transaction lock rejects a second
process sharing the same data directory, registry migrations are applied once
on start, and durable scheduled recovery resumes after restart. See
`src/server/index.ts` for the full set of forwarded environment variables.

## Providers

AgentSecret integrates with customer-controlled vault and secret providers.
The supported modes are Bitwarden Secrets Manager, Bitwarden Password Manager,
1Password service accounts and LastPass. Provider write and read capabilities
vary by mode and are reported per alias; unsupported operations fail closed
rather than silently degrading. 1Password Connect is deferred.

## CLI and MCP

The MIT-licensed standalone CLI (`bin/agentsecret.js`, built to
`dist/cli.mjs`) and the MCP companion let agents and scripts call the broker
over HTTP with DPoP. A ready-to-use agent skill ships in
`skills/agentsecret-cli`.

## Rust supervisor

`native/agentsecret-supervisor` is an MIT-licensed Rust tool that plans and
stages execution for the Docker Sandboxes backend. The `agentsecret run`
command remains disabled until the packaged runtime and strict credential
mediation pass independent qualification; the supervisor and its tests are
included so that qualification can be reproduced from source.

## License

The server, shared core and dashboard UI are licensed under the GNU Affero
General Public License, version 3 only, with a commercial alternative; see
[LICENSE-AGPL.md](LICENSE-AGPL.md), [NOTICE.md](NOTICE.md) and
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md). The CLI, MCP client utilities,
protocol helpers in [protocol/](protocol/) and the Rust supervisor in
[native/agentsecret-supervisor](native/agentsecret-supervisor) are licensed
under the MIT license ([protocol/LICENSE-MIT.md](protocol/LICENSE-MIT.md)).

Network users of the AGPL components are entitled to the Corresponding Source
of the exact version serving them; see [docs/source-access.md](docs/source-access.md).

## Documentation

- [docs/source-access.md](docs/source-access.md) — AGPL section 13 source access
- [docs/cli-release.md](docs/cli-release.md) — verifying an attested CLI release

## Checks

```sh
npm run typecheck
npm test
npm run build
trunk check --ci --all
```

The test suite runs the platform-neutral unit harness, the Node/SQLite server
conformance suite, the Turso registry adapter suite and the local-security
provider/CLI suites against synthetic fixtures. Live provider, host and
runtime acceptance are tracked separately and are not implied by these tests.
