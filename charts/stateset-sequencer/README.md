# StateSet Sequencer Helm chart

This is the canonical Helm deployment for StateSet Sequencer.

Create or externally manage a Secret containing:

- `DATABASE_URL`
- either `BOOTSTRAP_ADMIN_API_KEY` or `JWT_SECRET`
- `PAYLOAD_ENCRYPTION_KEY` when `config.payloadEncryptionMode=required`

Then install:

```bash
helm upgrade --install sequencer ./charts/stateset-sequencer \
  --namespace sequencer --create-namespace \
  --set secrets.existingSecret=stateset-sequencer-secrets
```

Anchoring and settlement are disabled by default. Enabling either feature makes
its corresponding Secret keys mandatory in the rendered Deployment. See
`values.yaml` for all configuration and scaling options.
