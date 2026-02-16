#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP_DIR="${ROOT_DIR}/.tmp"
TARGET_DIR="${TMP_DIR}/target"

mkdir -p "${TMP_DIR}" "${TARGET_DIR}"

export TMPDIR="${TMP_DIR}"
export RUSTC_TMPDIR="${TMPDIR}"
export CARGO_TARGET_DIR="${TARGET_DIR}"
export CARGO_INCREMENTAL=0

exec cargo "$@"
