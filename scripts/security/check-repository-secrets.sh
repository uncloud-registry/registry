#!/usr/bin/env bash
# Deterministic fail-closed secret gate for this repository.
#
# This is the *enforced* local gate: it runs purely on git and grep, with no
# external binary dependency (Gitleaks is *not* assumed to be installed; the
# .gitleaks.toml config targets the Gitleaks engine when CI runs it). A real
# Gitleaks invocation is never part of this gate, so it cannot silently no-op.
set -euo pipefail

# Fail closed: there is no meaningful scan outside a git work tree.
if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]; then
  echo "error: check-repository-secrets.sh must run inside a git worktree" >&2
  exit 2
fi

# Resolve the repository top-level and anchor all subsequent scan/path
# operations to it. git grep and git ls-files default to the CURRENT
# directory (not the repo root), so without this a nested invocation would
# miss credentials and tracked runtime files elsewhere in the repo. Fail
# closed if the top-level cannot be resolved.
top="$(git rev-parse --show-toplevel 2>&1)" || {
  echo "error: cannot resolve repository top-level:" >&2
  printf '%s\n' "$top" >&2
  exit 2
}
if [ ! -d "$top" ]; then
  echo "error: repository top-level is not a directory: $top" >&2
  exit 2
fi
cd "$top" || { echo "error: cannot cd to $top" >&2; exit 2; }

# Credential-like patterns enforced on tracked files.
#  - PEM headers: RSA / EC / OPENSSH, and PKCS#8 ('BEGIN[ ]PRIVATE KEY';
#    '[ ]' instead of a literal space keeps this source text from matching its
#    own PKCS#8 token).
#  - GitHub classic tokens (ghp_/gho_/ghu_/ghs_/ghr_) and fine-grained
#    github_pat_ tokens.
#  - AWS access key ID (AKIA) and temporary session key (ASIA).
pattern='(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|BEGIN[ ]PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(AKIA|ASIA)[0-9A-Z]{16})'

# git grep exit codes: 0 = matches found, 1 = no match, anything else = fatal.
# A fatal git failure must NOT look like "clean".
grep_output="$(git grep -nE "$pattern" -- ':!go.sum' 2>&1)" || grep_rc=$?
grep_rc="${grep_rc:-0}"
case "$grep_rc" in
  0)
    echo "credential-like material found:" >&2
    printf '%s\n' "$grep_output" >&2
    exit 1
    ;;
  1)
    : # no matches: clean
    ;;
  *)
    echo "error: git grep failed (rc=$grep_rc):" >&2
    printf '%s\n' "$grep_output" >&2
    exit 2
    ;;
esac

# Sensitive runtime files must not be tracked. git ls-files --error-unmatch
# returns 0 only when the path is tracked; anything else is either "untracked"
# (ok) or an operational error (fail closed).
for path in controlplane.db .env; do
  set +e
  git ls-files --error-unmatch -- "$path" >/dev/null 2>&1
  rc=$?
  set -e
  case "$rc" in
    0)
      echo "error: sensitive runtime file is tracked: $path" >&2
      exit 1
      ;;
    1)
      : # untracked, as required
      ;;
    *)
      echo "error: git ls-files failed (rc=$rc) for $path" >&2
      exit 2
      ;;
  esac
done

echo "repository secret scan clean"