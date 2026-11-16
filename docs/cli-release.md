# Verifying a standalone CLI release

The `Versioned CLI release` workflow builds `dist/cli.mjs` from the lockfile at a version-matched tag, creates a GitHub build-provenance attestation, verifies the artifact against the exact repository and workflow identity, then publishes it as `cli.mjs`. The workflow rejects tags whose version differs from `package.json`, tag commits outside the repository's default branch, and any modified copy that fails attestation verification.

The commands below describe the consumer check for a published attested release asset.

Download and verify before running the file:

```sh
gh release download v3.0.0 --repo OWNER/REPO --pattern cli.mjs --dir .
gh attestation verify ./cli.mjs \
  --repo OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/cli-release.yml
node ./cli.mjs --help
```

Replace `OWNER/REPO` with the repository that publishes this project. Verification checks the artifact digest and the provenance signer; review the attested source and workflow before trusting the resulting program. A same-origin checksum does not replace this verification. GitHub documents artifact attestations for public repositories on Free, Pro and Team plans and for private/internal repositories on Enterprise Cloud; the workflow has no unsigned-release fallback.

This attestation covers the standalone CLI module. It does not qualify or attest a sandbox/runtime artifact or prove runtime security; native host, OS-store, tamper, cancellation and cleanup acceptance are tracked separately.

References: [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), [GitHub CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify), [GitHub action dependency pinning guidance](https://docs.github.com/en/actions/how-tos/secure-your-work).
