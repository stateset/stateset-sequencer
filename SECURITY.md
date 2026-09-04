# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the StateSet Sequencer, please report it responsibly:

**Email:** security@stateset.io

Please do **not** open a public GitHub issue for security vulnerabilities.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 7 days
- **Resolution Target:** Depends on severity

## Security Best Practices

For detailed security guidance on deploying and operating the sequencer, see [docs/SECURITY.md](docs/SECURITY.md).

### Quick Checklist

- [ ] Use TLS for all connections
- [ ] Inject secrets from a secrets manager or Kubernetes Secret; never commit env files
- [ ] Rotate keys regularly (agent keys: 90 days, sequencer key: 180 days)
- [ ] Enable rate limiting in production
- [ ] Use dedicated database users with minimal privileges
- [ ] Never use the dev keys from `docker-compose.yml` in production

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.7.x   | :white_check_mark: |
| < 0.7   | :x:                |

## Tracked Transitive Advisories

The CI security jobs run both `cargo audit` and `cargo deny`. Informational
unsoundness and maintenance warnings are reviewed even when they are not fatal:

- `RUSTSEC-2026-0253` affects `lru 0.16.4`, currently pulled by
  `alloy-provider`. The flaw requires a panicking `Drop` implementation on an
  LRU key plus unwind recovery. Alloy's instantiated keys in this build are
  integer block numbers and fixed-size hashes, neither of which has a custom
  `Drop`. The first upstream fix is `lru 0.18.2`; migrate when Alloy supports
  it, or as part of the planned Alloy 2 upgrade.
These are documented risk acceptances, not audit suppressions. CI continues to
report them so an upstream resolution is visible immediately.
