#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-sequencer}"
DEPLOYMENT="${DEPLOYMENT:-stateset-sequencer}"

kubectl apply -k k8s

# Optional: enable Google Managed Prometheus scraping + alerting rules
if kubectl api-resources | grep -q '^podmonitorings[[:space:]]'; then
  kubectl apply -f k8s/gmp/podmonitoring.yaml
  kubectl apply -f k8s/gmp/rules.yaml
fi

kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT}" --timeout=10m
kubectl -n "${NAMESPACE}" get pods -l app.kubernetes.io/name=stateset-sequencer -o wide

