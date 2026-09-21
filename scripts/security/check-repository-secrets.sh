#!/usr/bin/env bash
set -euo pipefail

git grep -nE '(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})' -- ':!go.sum' && {
  echo "credential-like material found" >&2
  exit 1
}

for path in controlplane.db .env; do
  if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
    echo "sensitive runtime file is tracked: $path" >&2
    exit 1
  fi
done