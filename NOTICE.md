# AgentSecret License Notice

Copyright (c) 2026 Omar. All rights reserved by the copyright holder; code is
licensed as stated below and in each package manifest.

## Server, core and UI (AGPL-3.0-only)

The AgentSecret server, platform-neutral core, HTTP/MCP application logic,
dashboard UI and deployment configuration are licensed under the GNU Affero
General Public License, version 3 only ([LICENSE-AGPL.md](LICENSE-AGPL.md)).
Network use of these components grants every user the right to receive the
Corresponding Source of the exact version that serves them. A commercial
license is available as an alternative for parties who cannot satisfy AGPL
obligations; contact the copyright holder before distributing or relicensing.

## CLI, MCP client, protocol utilities and Rust tools (MIT)

The AgentSecret CLI, MCP client utilities, protocol helper package
([protocol/](protocol/)) and the Rust supervisor/tools
([native/agentsecret-supervisor](native/agentsecret-supervisor)) are licensed
under the MIT license ([protocol/LICENSE-MIT.md](protocol/LICENSE-MIT.md)).
These components must not import, link or bundle AGPL server modules; the
repository's automated import and bundle checks enforce that boundary.

## Third-party dependencies

Runtime TypeScript dependencies and their licenses:

| Dependency                | Version | License |
| ------------------------- | ------- | ------- |
| jose                      | 6.2.14  | MIT     |
| @tursodatabase/serverless | 1.4.1   | MIT     |

Development/test dependencies are not shipped as separate runtime modules.
However, `scripts/build-cli.mjs` bundles `@1password/sdk` and its transitive
JavaScript dependencies into `dist/cli.mjs` and embeds the SDK's `sdk-core`
WebAssembly payload. Their licenses and available upstream notices are
recorded in the `dist/THIRD-PARTY-NOTICES.txt` file shipped with the CLI.
The packed artifact is the distribution boundary used for this audit.

Web dashboard dependencies: react, react-dom, lucide-react (MIT); dev-only:
vite, @vitejs/plugin-react, typescript, @types/react, @types/react-dom
(MIT/Apache-2.0 as declared in their manifests).

Rust supervisor dependencies (serde 1.0.229, serde_json 1.0.154, rustix 1.1.6)
are MIT OR Apache-2.0 per their crates.io manifests; the Rust tool remains MIT
under this repository's dual-license choice, which both upstream licenses
permit.

No third-party code has been imported into this repository's source tree beyond
the dependencies declared above and their transitive dependencies in the lock
files. Contributions of new code must carry compatible licenses; contributions
to AGPL server components require the contributor to grant rights sufficient
for the project's commercial-licensing alternative (a contributor license
agreement or equivalent explicit grant).
