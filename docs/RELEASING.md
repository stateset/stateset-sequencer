# Releasing StateSet Sequencer

The automatic sequencer release publishes the server binary and container from
the same CI-validated commit. Keep the versions in `Cargo.toml`,
`cli/package.json`, `cli/package-lock.json`, and `sdk/python/pyproject.toml`
identical, and add the matching dated section to `CHANGELOG.md`.

The automatic release run starts only after every CI job succeeds on the default
branch. It creates an annotated `v<version>` tag when one is absent and publishes
the GitHub release with checksums and provenance. SDK registry publication is
optional and requires a manual `release` workflow dispatch for that existing tag:

- `@stateset/sequencer-sdk` to npm from the protected `npm` environment.
- `stateset-sequencer-sdk` to PyPI from the protected `pypi` environment.

## Optional one-time registry setup

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

## Publish or retry SDK packages

When registry publication is desired, configure the registries and manually
run the `release` workflow with the existing `v<version>` tag. If a publication
fails, correct the registry configuration and dispatch the same tag again.
The workflow checks each registry independently,
skips versions that are already present, and publishes only missing packages
from the commit referenced by that tag. It then verifies that both packages
can be resolved from their public registries.

Do not bump or reuse the version merely to recover from a registry outage or
configuration error. Package registry versions are immutable.
