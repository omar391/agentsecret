# AgentSecret native supervisor request boundary

This crate defines the first typed boundary for `agentsecret run`: an explicit
guest executable, literal argv, a workspace working directory, declared file
transfers, alias/reference bindings, and exact outbound HTTPS rules. Secret
values are not part of the request schema, and unknown fields fail closed.

`parse_run_request` validates syntax only. `stage_declared_files` copies only
declared regular files beneath the launcher's trusted project root into a new
private workspace. It pins the root directory, opens each path component
without following symlinks, rejects hard-linked files, applies byte bounds,
removes partial workspaces on failure, and returns a manifest for the backend.
Read-only permissions in that workspace are a defense in depth measure; the VM
backend must enforce read-only grants at its own mount boundary.

The crate still does not authorize aliases, bind or inject credentials, start
Docker Sandboxes, enforce egress, or qualify a runtime. `cli.mjs` therefore
keeps `run` disabled. The macOS v0.51.0 Docker Sandboxes artifact still lacks
matching provenance, and the product supervisor has not passed adversarial
guest qualification.

The `agentsecret-supervisor stage --host-root PATH --destination PATH` binary
reads the bounded request from stdin and writes only a reference/path/mode/size
manifest to stdout. It does not print source paths or file contents and does
not launch the workload. The Node coordinator does not call this prototype yet.

`docker_policy::compile_sbx_command_plan` compiles a validated request and
staged-file manifest to separate `sbx create`, policy-audit, sandbox-scoped
HTTP-allow, `sbx exec`, and cleanup argv. It uses an empty primary workspace,
an explicit `/workspace` mount, and exact additional file mounts with `:ro` on
read-only declarations. It requires private empty scratch directories and
checks each staged file's canonical path, link count, length and permission
mode before including it in argv. It refuses secret reference bindings because
no qualified credential adapter exists. `allow_rule_argv` is the low-level rule
compiler used by this plan. Sandbox creation disables the shared host skills
store and static MCP registrations; a future host runner must also remove SSH
agent socket variables before spawning `sbx`. The plan also requests global and
run-name-scoped credential metadata for private preflight. The runner must
inspect these records in memory, never log or return them, and reject any
unapproved host credential mapping before starting guest commands.

These functions only construct argv; they do not execute `sbx`, verify its JSON
policy schema, establish a deny-by-default effective policy, or qualify nested
mount and read-only behavior. The local preset is machine-wide, and organization
policy can make local allow rules inactive or broaden access. A future launcher
must inspect both account and sandbox policy and fail closed when it cannot
prove the effective rule set. The exact-v0.51.0 runtime still lacks matching
artifact provenance and has not been installed or run.

The `gateway` module parses the guest's bounded placeholder request, reuses the
broker's exact-request capability contract, and sends one request to
`/proxy/capability` with the capability supplied out-of-band. It refuses unsafe
HTTPS targets, reserved transport headers, non-identity secrets, duplicate or
missing body placeholders, unsafe redirects, oversized responses, and retries
after ambiguous outcomes. Network and timeout failures are terminal
`gateway_outcome_unknown` results: a hidden side effect may already have
occurred, so reconciliation must precede any new attempt. Broker headers are not
reflected to the guest. The Rust transport uses rustls with redirects, proxy
environment lookup, cookies, compression, and credential discovery disabled.
The local-companion resolver currently fails closed; a qualified implementation
must be explicitly authorized before it can resolve credentials outside the
broker path.

The `agentsecret-supervisor gateway --broker-origin URL --capability-file PATH`
command reads the guest request from stdin, writes a non-secret JSON receipt to
stdout, and exits non-zero for terminal unknown outcomes. The capability is read
from a regular file that must not be readable or writable by group or others
(mode `0600`); a missing, non-regular, oversized, or broadly readable file is
refused before any transport is opened. The testing-only
`AGENTSECRET_GATEWAY_TESTING_ORIGIN=1` environment variable additionally
permits loopback HTTP origins so deterministic tests can use a local stub
broker; production callers must use HTTPS.

The `mcp --self PATH --broker-origin URL --capability-file PATH` command is the
host-side Docker MCP stdio adapter. It keeps the capability out of the guest,
advertises only `proxy_http_request`, validates exact tool arguments, and passes
each request to the gateway child process with the same capability file path.
Because the capability is only ever read from the file, neither the MCP
registration nor either process argument list contains it. Docker supplies the
supported guest-to-host route; AgentSecret supplies the caller capability check.
A native Docker local-stdio registration was observed to forward
unauthenticated probe calls and therefore is not accepted as the credential
boundary.

Cargo build outputs must remain outside this crate and repository. Set
`CARGO_TARGET_DIR=/tmp/cargo-targets/<worktree-root-sha256>` for each Cargo
command, where the hash is computed from the canonical worktree path.

## Git packet framing

`git_wire` provides a bounded, binary-safe pkt-line reader and encoder. It
preserves flush, delimiter, response-end and empty-data packets as distinct
values, limits both each packet and the complete exchange, and makes framing
or I/O errors terminal. Debug output exposes payload lengths only. This is
framing infrastructure, not an authorized Git gateway: it does not inspect
compressed pack objects for credential reflection, issue broker capabilities,
or enable guest Git execution.

The local integration test drives real `git upload-pack --stateless-rpc`,
round-trips its sideband response through the codec byte-for-byte, reconstructs
the pack, and has `git index-pack --strict` and `git cat-file` verify the
original 300,000-byte binary blob. All Git operations occur in disposable
task-local repositories with isolated configuration and an empty hook path.

The MCP reader now stops at its message-size bound before reading a full line;
its regression keeps stdin open after an oversized prefix to verify that
neither newline nor EOF is needed for refusal.
