#!/usr/bin/env bash
#
# Focused regression tests for scripts/security/check-repository-secrets.sh.
# Creates throwaway temporary git repositories (never the project worktree)
# and asserts the scanner's fail-closed behavior.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN="$SCRIPT_DIR/check-repository-secrets.sh"
GIT=${GIT:-git}

pass=0
fail=0
say() { printf '%s\n' "$*"; }
fail_msg() { say "FAIL: $*"; fail=$((fail+1)); }
ok() { pass=$((pass+1)); }

# assert_exit <expected_rc> <dir> <label> : run the scan in <dir>, compare rc
assert_exit() {
  local expected="$1" dir="$2" label="$3" rc out
  out="$(mktemp "${TMPDIR:-/tmp}/scan-out.XXXXXX")"
  ( cd "$dir" && bash "$SCAN" >"$out" 2>&1 )
  rc=$?
  if [ "$rc" -eq "$expected" ]; then
    say "  ok: $label (rc=$rc)"
    ok
  else
    fail_msg "$label: expected rc=$expected got rc=$rc"
    sed 's/^/      /' "$out" >&2
  fi
  rm -f "$out"
}

# new_repo <dir> : fresh repo with one committed README, clean work tree
new_repo() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir"
  ( cd "$dir" && "$GIT" init -q \
      && "$GIT" config user.email t@example.test \
      && "$GIT" config user.name test \
      && printf 'ok\n' > README.md \
      && "$GIT" add README.md && "$GIT" commit -qm init )
}

# add_tracked <dir> <name> <content> : track a file with given content
add_tracked() {
  local dir="$1" name="$2" content="$3"
  printf '%s\n' "$content" > "$dir/$name"
  ( cd "$dir" && "$GIT" add "$name" && "$GIT" commit -qm "add $name" )
}

# Fixture credentials are assembled via concatenation so this test's own
# source text never contains a full live-looking secret; that keeps the
# repository scanner green on this very worktree.
fill() { printf 'A%.0s' $(seq 1 "$1"); }
pem_rsa=$(printf '%s %s' "-----BEGIN" "RSA PRIVATE KEY-----")
pem_ec=$(printf '%s %s' "-----BEGIN" "EC PRIVATE KEY-----")
pem_oss=$(printf '%s %s' "-----BEGIN" "OPENSSH PRIVATE KEY-----")
pem_pkcs8=$(printf '%s %s' "-----BEGIN" "PRIVATE KEY-----")
gh_classic="ghp_$(fill 30)"
gh_fine="github_pat_$(fill 30)"
aws_akia="AKIA$(fill 16)"
aws_asia="ASIA$(fill 16)"

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/scan-test.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT

say "== clean repo passes =="
clean_dir="$tmpdir/clean"
new_repo "$clean_dir"
assert_exit 0 "$clean_dir" "clean repo passes"

say "== each credential family is rejected =="
i=0
for tok in "$pem_rsa" "$pem_ec" "$pem_oss" "$pem_pkcs8" "$gh_classic" "$gh_fine" "$aws_akia" "$aws_asia"; do
  i=$((i+1))
  repo="$tmpdir/fam$i"
  new_repo "$repo"
  add_tracked "$repo" "secret.txt" "prefix $tok suffix"
  assert_exit 1 "$repo" "credential family $i rejected"
done

say "== running outside a git worktree fails =="
plain="$tmpdir/plain"
rm -rf "$plain"; mkdir -p "$plain"
printf 'x\n' > "$plain/f.txt"
assert_exit 2 "$plain" "running outside a git worktree fails"

say "== tracked sensitive runtime files are rejected =="
db="$tmpdir/db"
new_repo "$db"
add_tracked "$db" "controlplane.db" "some database bytes"
assert_exit 1 "$db" "tracked controlplane.db rejected"

env="$tmpdir/env"
new_repo "$env"
add_tracked "$env" ".env" "FOO=bar"
assert_exit 1 "$env" "tracked .env rejected"

say "== git operational errors do not return success =="
op="$tmpdir/op"
new_repo "$op"
printf 'garbage-not-an-index' > "$op/.git/index"
assert_exit 2 "$op" "git operational error (corrupt index) does not return success"

say ""
say "passed: $pass  failed: $fail"
if [ "$fail" -gt 0 ]; then
  say "RESULT: FAIL"
  exit 1
fi
say "RESULT: PASS"