# Public-core retroactive review evidence

Evidence recorded on 2026-11-19 for T-024, T-025, and T-026. Authenticated
review and landing receipts are maintained separately in the private release
ledger; this document records source evidence and is not a review receipt.

## Published source and evidence candidate

GitHub published v3.0.0 on 2026-11-16 at 02:25:58 UTC. Both the remote tag ref
and the local tag resolve to commit `ef237ad3813ca04a836ae422ef48bba498ad7fec`,
with tree `ce385a7892862573ebed6e6593af613d4506ad5b`. This document is a later,
uncommitted evidence candidate. It is absent from the tagged tree.
[GitHub release](https://github.com/omar391/agentsecret/releases/tag/v3.0.0)

The configured Review Loop base is `bf99bb72e211dce123ac1ac7707821cb512674ab`.
The comparison from that base to the tagged commit contains one commit. The
comparison from that base to the evidence candidate also includes this document.
The audit below records evidence for the initial snapshot, the full published
commit range, and the release target.

## Initial public snapshot

The initial commit `7ba45dc71dc2288dc8335efd5445b3be7dcad7a3` has tree
`e13ef7a247f5d219682598d30982c244f3330470` and no parent.
`git rev-list --max-parents=0 v3.0.0` returned that commit as the sole root,
and `git rev-list --count v3.0.0` returned four. The tagged ancestry therefore
starts at the public snapshot.

The audit compared the snapshot with the empty Git tree
`4b825dc642cb6eb9a060e54bf8d69288fbee4904` to include all 175 files.
`git diff --check` passed for that comparison. The NUL-delimited inventory
from `git ls-tree -r -z 7ba45dc71dc2288dc8335efd5445b3be7dcad7a3` had SHA-256
`93d8caa55ea4ecd74c90ebebc63ee4b5209a00e022f8ede4299839f11ed20d90`.
It contained 174 regular nonexecutable files and one regular executable,
with zero symlinks and zero Git links.

The inventory check found no `data/`, `docs/evidence/`,
`docs/key-custody-and-rotation.md`, or `dev-learnings.md`. It also found no
`.env` variants, common private-key or database file extensions, or files
under `tmp/`, `.agents/`, or `.codex/`. A text search for local workstation
paths and private-key headers surfaced only synthetic workstation paths in
native supervisor tests. Inspection of the two launch-video files' metadata
and the accompanying contact sheet found render metadata and public-facing
promotional content. Gitleaks 8.30.1 reported zero findings from the root
patch using `gitleaks git --log-opts='--max-count=1 7ba45dc' --redact`
(one commit, 2,113,359 bytes). Comparison against the original publication
allowlist still requires that allowlist as evidence.

## Three commits after the snapshot

The range `7ba45dc..ef237ad` contains the following commits in order. Each
patch changes only `tests/bitwarden-password-manager-cli.test.mjs` and
`tests/lastpass-cli.test.mjs`.

| Commit                                     | Observed change                                                                                                                       |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `088ce22719934ead9849db75364b9f9426a43dc8` | Adds a parent-process platform override to both synthetic macOS companion tests.                                                      |
| `bf99bb72e211dce123ac1ac7707821cb512674ab` | Converts both parent-process overrides to accessors.                                                                                  |
| `ef237ad3813ca04a836ae422ef48bba498ad7fec` | Moves the override into each spawned CLI process's preload. The two inserted preload lines are the entire net diff from the snapshot. |

`git diff-tree --root --check -r` passed individually for all four commits,
and `git diff --check 7ba45dc ef237ad` passed for the range.
`gitleaks git --log-opts='7ba45dc..ef237ad' --redact` reported zero findings
across the three subsequent patches (578 bytes).

## Tagged-source checks and CLI artifact

The CLI release workflow completed successfully on 2026-11-16 with head
`ef237ad3813ca04a836ae422ef48bba498ad7fec`. It verified tag and default-branch
ancestry, ran typecheck and the full test suite, and verified the attested CLI
and rejection of a modified copy before publishing. The workflow completed
the download and verification of the public asset at 02:26:06 UTC.
[GitHub Actions run 43792008126](https://github.com/omar391/agentsecret/actions/runs/43792008126)

The 2026-11-19 audit downloaded the published `cli.mjs` again. Its SHA-256
`8ad15ef96f2c296706f70ddab9044d11d726a2a0038e48b3d2e27038c4be2079`
matched the GitHub release asset metadata. `gh attestation verify` passed with
repository `omar391/agentsecret`, signer workflow
`omar391/agentsecret/.github/workflows/cli-release.yml`, source ref
`refs/tags/v3.0.0`, and the full tagged source commit pinned. Verification
of a modified copy returned HTTP 404 for its changed digest.
`node --check` and `node cli.mjs --help` passed on the verified download.

On 2026-11-19, `npm test` and `npm run typecheck` exited 0 with locked
dependencies and Node.js 22.16.0 in a clean checkout of the tagged source.
Two tests used their existing skips because a native supervisor build was
unavailable. Both synthetic macOS companion CLI tests also passed in a
direct run with zero skips.

The tagged source's `npm run trunk:check` checked 143 files and exited 1.
Prettier reported eight unformatted paths.

- `cli/index.ts`
- `cli/providers/bitwarden-password-manager.ts`
- `cli/providers/lastpass.ts`
- `scripts/accept-codex-host.mjs`
- `src/state/authority-kernel.ts`
- `tests/bitwarden-password-manager.test.ts`
- `tests/docker-runtime.test.ts`
- `tsconfig.json`

The original evidence candidate changed only this document, and its whitespace,
formatting, and Gitleaks checks passed. The source archive regression test
passed, and the rebuilt candidate archive contained this document byte for
byte. The archive built from the clean tagged checkout had no copy of this
document. Trunk reported the same eight failures with that candidate present;
the immutable v3.0.0 tag itself remains unqualified by the Trunk gate.

On 2026-11-20 the release owner authorized a formatting-only successor
candidate in the review worktree. Only the eight listed paths were changed,
using the repository's Trunk formatter, and those changes are formatting-only.
This evidence document is the additional changed path relative to the v3.0.0
tag. On the resulting worktree, `npm run trunk:check` checked 144 files and passed,
`npm run typecheck` passed, and the full `npm test` run passed: 52 root Node
tests, 10 Turso adapter tests, 15 Node conformance tests, 75 passing local
security tests with the same two documented supervisor skips, and 5 license
boundary tests. `git diff --check` passed. Gitleaks 8.30.1 reported zero
findings over the four-commit history, the reviewed base-to-HEAD range, and the
working tree. The private release ledger is the designated destination for the
authenticated review and landing receipts for this formatting-only successor.
Both review and landing were pending at the time of this snapshot. No successor release tag
or CLI artifact is described by this source-evidence document.
The GitHub release notes contained no retroactive receipt reference when
checked on 2026-11-19.
