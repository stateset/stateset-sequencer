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

Never publish a package locally from an unvalidated working tree. If any
publication job fails, correct the registry configuration and rerun that job;
do not reuse a version that a registry already accepted.
