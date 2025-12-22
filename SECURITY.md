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
- [ ] Store secrets in a secrets manager (not env files)
- [ ] Rotate keys regularly (agent keys: 90 days, sequencer key: 180 days)
- [ ] Enable rate limiting in production
- [ ] Use dedicated database users with minimal privileges
- [ ] Never use the dev keys from `docker-compose.yml` in production

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |
