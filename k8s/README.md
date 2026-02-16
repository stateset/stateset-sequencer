# Kubernetes (GKE) Deployment

This repo includes a minimal Kustomize deployment for the StateSet Sequencer in `k8s/`.

## Apply (Config + Workloads)

1. Ensure the `sequencer-secrets` secret exists in the `sequencer` namespace.
   - Use `k8s/secret.example.yaml` as a template (do not commit real secrets).

2. Apply the manifests:

```bash
kubectl apply -k k8s
```

## Monitoring (Google Managed Prometheus)

If your GKE cluster has Google Managed Prometheus enabled, apply:

```bash
kubectl apply -f k8s/gmp/podmonitoring.yaml
kubectl apply -f k8s/gmp/rules.yaml
```

These resources scrape `/metrics` using `Authorization: ApiKey ...` from the `BOOTSTRAP_ADMIN_API_KEY`
stored in `sequencer-secrets`.

