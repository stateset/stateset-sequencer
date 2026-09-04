# Releasing StateSet Sequencer

One sequencer release publishes the server binary, container, Node SDK, and
Python SDK from the same CI-validated commit. Keep the versions in `Cargo.toml`,
`cli/package.json`, `cli/package-lock.json`, and `sdk/python/pyproject.toml`
identical, and add the matching dated section to `CHANGELOG.md`.

The release workflow runs only after every CI job succeeds on the default
branch. It creates an annotated `v<version>` tag when one is absent, publishes
the GitHub release with checksums and provenance, then publishes:

- `@stateset/sequencer-sdk` to npm from the protected `npm` environment.
- `stateset-sequencer-sdk` to PyPI from the protected `pypi` environment.

## One-time registry setup

1. Create the GitHub environments `npm` and `pypi`; require reviewer approval
   for both.
2. On PyPI, create a pending trusted publisher for organization `stateset`,
   repository `stateset-sequencer`, workflow `release.yml`, environment
   `pypi`, and project name `stateset-sequencer-sdk`.
3. npm requires the package to exist before trusted publishing can be attached.
   Put a short-lived granular `NPM_TOKEN` in the `npm` environment for the first
   release only. Then configure the package's GitHub Actions trusted publisher
   for `stateset/stateset-sequencer`, workflow `release.yml`, environment
   `npm`, and allow `npm publish`.
4. Remove `NPM_TOKEN` after the first successful release and disallow token
   publishing in npm. Later releases authenticate only with short-lived OIDC
   credentials and automatically carry npm provenance.

Never publish a package locally from an unvalidated working tree.

## Retry a partial release

If an SDK publication fails after the GitHub release exists, correct the
registry configuration and manually run the `release` workflow with the
existing `v<version>` tag. The workflow checks each registry independently,
skips versions that are already present, and publishes only missing packages
from the commit referenced by that tag. It then verifies that both packages
can be resolved from their public registries.

Do not bump or reuse the version merely to recover from a registry outage or
configuration error. Package registry versions are immutable.
