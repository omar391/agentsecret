# AGPL Source Access

The AgentSecret server, core and UI are licensed under the GNU Affero General
Public License, version 3 only. Section 13 of that license grants every user
who interacts with the software through a network the right to receive the
Corresponding Source of the exact version serving them.

## For the public deployment

The release build runs `npm run build:source-access` before the dashboard build.
That command archives the materialized release source tree, including build
inputs and lock files, and writes the archive, SHA-256 digest and revision
manifest into the dashboard's static asset tree. The manifest records both the
Git revision and a SHA-256 digest of the archived source tree, so builds from a
modified checkout still identify their exact source bytes.
It excludes private operational evidence and key-custody notes, which are not
Corresponding Source. The Worker static asset binding serves these files on the
deployment origin:

- [`/source.tar.gz`](https://agentsecret.astronlab.com/source.tar.gz)
- [`/source.tar.gz.sha256`](https://agentsecret.astronlab.com/source.tar.gz.sha256)
- [`/source-revision.json`](https://agentsecret.astronlab.com/source-revision.json)

The source archive and its digest are also included in the self-hosted npm
release package. It contains the Node server source, required migrations and
AGPL license, so an operator can rebuild and run the server from that source
distribution. Verify an archive with `sha256sum -c source.tar.gz.sha256`.

## For self-hosted deployments

A self-hosted operator satisfies section 13 by distributing the source
archive that ships with the release they deployed (the same repository snapshot
and lock files), unmodified or with their own modifications carried through.
The repository's build tooling is part of the Corresponding Source and stays
in the archive. The archive contains a revision and file manifest, allowing
`npm run build:source-access` to rebuild from an extracted archive without
Git metadata.

## What is not covered

Credentials, private deployment identifiers, private operational evidence and
customer data are not part of the Corresponding Source and are never included
in a source archive. The MIT-licensed CLI and protocol utilities carry no
AGPL obligations of their own.
