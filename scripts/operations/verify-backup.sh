#!/usr/bin/env bash
# verify-backup.sh — verify a uncloud-registry backup archive (Task 26).
#
# Checks, in order, and exits nonzero on the FIRST gap while still reporting
# every detected gap:
#   1. Archive structure: manifest.json + SHA256SUMS present and parseable.
#   2. File completeness: every file listed in the manifest and in SHA256SUMS
#      exists inside the archive.
#   3. SHA-256 checksums: every file in SHA256SUMS re-hashes to its recorded
#      digest (tamper detection).
#   4. Control-plane database integrity: PRAGMA integrity_check == ok.
#   5. Staging database integrity: PRAGMA integrity_check == ok.
#   6. Schema versions: control-plane schema_migrations and staging
#      staging_schema versions match what the manifest recorded at backup
#      time (a restored DB that no longer carries its recorded schema is a
#      sign of corruption or an incomplete restore).
#   7. Required secret identifiers: the manifest's required_secrets accounting
#      is complete — every identifier is either IN the archive or explicitly
#      marked excluded. Secret VALUES are never read, printed, or hashed-by-
#      value by this script; only identifiers and presence are reported.
#      When --secrets-dir is given, excluded identifiers are additionally
#      confirmed present (and owner-only) in the live secrets directory.
#   8. Deployment configuration present: compose.yaml is listed, exists, and
#      its recorded hash matches.
#
# Output is a fixed, human-readable report. Exit codes: 0 = verified,
# 1 = verification gap(s), 2 = usage error. Errors never contain secret
# values.
set -euo pipefail

# --- argument parsing -------------------------------------------------------

usage() {
  cat >&2 <<'EOF'
usage: verify-backup.sh --backup-dir DIR [--secrets-dir DIR]

  --backup-dir DIR   backup archive root (must contain manifest.json)
  --secrets-dir DIR  optional live secrets directory; every manifest-excluded
                     secret identifier is then confirmed present there
                     (presence + owner-only mode, values never read)
EOF
}

BACKUP_DIR=""
SECRETS_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --backup-dir)
      BACKUP_DIR="${2:-}"
      shift 2
      ;;
    --secrets-dir)
      SECRETS_DIR="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "$BACKUP_DIR" ]; then
  echo "error: --backup-dir is required" >&2
  usage
  exit 2
fi
if [ ! -d "$BACKUP_DIR" ]; then
  echo "error: backup directory does not exist: $BACKUP_DIR" >&2
  exit 2
fi

MANIFEST="$BACKUP_DIR/manifest.json"
CHECKSUMS="$BACKUP_DIR/SHA256SUMS"
[ -f "$MANIFEST" ] || { echo "error: $BACKUP_DIR/manifest.json is missing" >&2; exit 2; }
[ -f "$CHECKSUMS" ] || { echo "error: $BACKUP_DIR/SHA256SUMS is missing" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || {
  echo "error: python3 is required (stdlib sqlite3 + hashlib)" >&2
  exit 2
}

# verify_report <name> <ok|FAIL> [detail]
# Accumulates a machine-readable and human-readable report; the final exit
# code is nonzero when any check has FAIL.
FAILURES=0
verify_report() {
  local name="$1" status="$2" detail="${3:-}"
  printf '  [%s] %s' "$status" "$name"
  [ -z "$detail" ] || printf ' — %s' "$detail"
  printf '\n'
  if [ "$status" = "FAIL" ]; then
    FAILURES=$((FAILURES + 1))
  fi
}

echo "Verifying backup archive: $BACKUP_DIR"

# --- 1+2+3+4+5+6+8: structural, checksum, integrity, schema, config ---------
# A single python3 pass keeps the whole verification read-only and gives one
# consolidated gap list instead of fail-fast output.
VERIFY_SECRETS_DIR="$SECRETS_DIR" python3 - "$MANIFEST" "$CHECKSUMS" "$BACKUP_DIR" <<'PY'
import hashlib
import json
import os
import sqlite3
import sys

manifest_path, checksums_path, backup_dir = sys.argv[1], sys.argv[2], sys.argv[3]
failures = []

# 1. manifest parses and has the required shape.
try:
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
except Exception as exc:  # noqa: BLE001 - fixed report line
    print("  [FAIL] manifest.json parse — %s" % exc)
    sys.exit(1)

if manifest.get("schema") != "uncloud-registry-backup/v1":
    failures.append("manifest schema tag is not uncloud-registry-backup/v1")
if not isinstance(manifest.get("files"), list) or not manifest["files"]:
    failures.append("manifest files list is missing or empty")

# 2. checksum file parses; every line must be "<64 hex>  <relative path>".
try:
    with open(checksums_path, "r", encoding="utf-8") as f:
        checksum_lines = f.read().strip().splitlines()
except Exception as exc:  # noqa: BLE001
    failures.append("SHA256SUMS unreadable: %s" % exc)
    checksum_lines = []

recorded = {}
for line in checksum_lines:
    parts = line.split("  ", 1)
    if len(parts) != 2 or len(parts[0]) != 64:
        failures.append("SHA256SUMS malformed line: %r" % line)
        continue
    digest, rel = parts[0], parts[1]
    if rel in recorded:
        failures.append("SHA256SUMS duplicate path: %r" % rel)
    recorded[rel] = digest

manifest_files = set(manifest.get("files", []))
# Every manifest-listed file must have a checksum and vice versa. SHA256SUMS
# is the index itself, not a payload, so it is exempt from the cross-check.
for rel in sorted(manifest_files):
    if rel not in recorded:
        failures.append("manifest file has no checksum: %r" % rel)
for rel in sorted(recorded):
    if rel == "SHA256SUMS":
        continue
    if rel not in manifest_files:
        failures.append("checksummed file not in manifest files list: %r" % rel)

# 3. every file exists and re-hashes; 8. compose.yaml hash matches manifest.
for rel, digest in sorted(recorded.items()):
    path = os.path.join(backup_dir, rel)
    if not os.path.isfile(path):
        failures.append("missing file: %r" % rel)
        continue
    try:
        with open(path, "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
    except Exception as exc:  # noqa: BLE001
        failures.append("cannot hash %r: %s" % (rel, exc))
        continue
    if actual != digest:
        failures.append("checksum mismatch: %r" % rel)

compose_rel = manifest.get("backup", {}).get("compose_config", "compose.yaml")
if compose_rel not in recorded:
    failures.append("deployment config %r missing from checksums" % compose_rel)
elif not os.path.isfile(os.path.join(backup_dir, compose_rel)):
    failures.append("deployment config %r missing from archive" % compose_rel)
recorded_compose = recorded.get(compose_rel)
expected_compose = manifest.get("compose_config_sha256")
if recorded_compose and expected_compose and recorded_compose != expected_compose:
    failures.append("deployment config hash does not match manifest record")

# 4+5. sqlite integrity of both databases inside the archive.
def integrity_ok(rel):
    path = os.path.join(backup_dir, rel)
    if not os.path.isfile(path):
        failures.append("database missing: %r" % rel)
        return False, "missing"
    try:
        con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        try:
            row = con.execute("pragma integrity_check").fetchall()
            ok = len(row) == 1 and row[0][0] == "ok"
            if not ok:
                failures.append("integrity_check failed for %r: %s" % (rel, row[:5]))
            return ok, ("ok" if ok else "corrupt")
        finally:
            con.close()
    except Exception as exc:  # noqa: BLE001
        failures.append("cannot open %r for integrity check: %s" % (rel, exc))
        return False, "unreadable"

cp_ok, cp_state = integrity_ok(manifest.get("backup", {}).get("controlplane_db", "controlplane.db"))
st_ok, st_state = integrity_ok(manifest.get("backup", {}).get("staging_db", "staging.db"))

# 6. schema versions recorded at backup time match the archived databases.
cp_rel = manifest.get("backup", {}).get("controlplane_db", "controlplane.db")
st_rel = manifest.get("backup", {}).get("staging_db", "staging.db")

def schema_version(rel, table, column):
    path = os.path.join(backup_dir, rel)
    try:
        con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        try:
            row = con.execute(
                "select max(%s) from %s" % (column, table)
            ).fetchone()
            return None if row is None or row[0] is None else int(row[0])
        finally:
            con.close()
    except Exception:  # noqa: BLE001 - schema drift reported as a gap below
        return None

cp_want = manifest.get("controlplane_schema_version")
cp_have = schema_version(cp_rel, "schema_migrations", "version") if cp_ok else None
if cp_ok and cp_want is not None and cp_have != cp_want:
    failures.append(
        "control-plane schema version drift: manifest=%s archived=%s"
        % (cp_want, cp_have)
    )
st_want = manifest.get("staging_schema_version")
st_have = schema_version(st_rel, "staging_schema", "version") if st_ok else None
if st_ok and st_want is not None and st_have != st_want:
    failures.append(
        "staging schema version drift: manifest=%s archived=%s" % (st_want, st_have)
    )

# 7. required secret identifiers accounting (identifiers only; never values).
required = manifest.get("required_secrets", [])
if not isinstance(required, list) or not required:
    failures.append("manifest required_secrets list is missing or empty")
included_ids = set()
for entry in required:
    ident = entry.get("id")
    if not isinstance(entry, dict) or not ident:
        failures.append("malformed required_secrets entry: %r" % entry)
        continue
    inc = entry.get("included") is True
    if inc:
        included_ids.add(ident)
        rel = entry.get("file")
        if rel and rel not in recorded:
            failures.append("included secret %r has no checksum entry" % ident)
    else:
        if entry.get("excluded_reason") is None:
            failures.append("excluded secret %r lacks an excluded_reason" % ident)
for ent in manifest.get("excluded_from_archive", []):
    if isinstance(ent, str) and ent in manifest_files and ent not in set(
        e.get("file") for e in required
    ):
        failures.append("excluded file %r is still present in the archive" % ent)

# 7b. when a live secrets dir is supplied, confirm excluded identifiers exist
# there (presence + owner-only mode). Values are never read.
secrets_dir = os.environ.get("VERIFY_SECRETS_DIR", "")
if secrets_dir:
    if not os.path.isdir(secrets_dir):
        failures.append("--secrets-dir is not a directory: %r" % secrets_dir)
    else:
        for entry in required:
            if entry.get("included") is True:
                continue
            ident = entry.get("id")
            live = os.path.join(secrets_dir, ident)
            if not os.path.isfile(live):
                failures.append(
                    "excluded secret %r not found in live secrets dir" % ident
                )
                continue
            mode = os.stat(live).st_mode & 0o777
            if mode & 0o022:
                failures.append(
                    "excluded secret %r is group/world writable (mode %04o)"
                    % (ident, mode)
                )
                continue
            print(
                "  [ok] excluded secret confirmed in --secrets-dir: %s" % ident
            )
if not secrets_dir and any(not e.get("included") for e in required):
    print(
        "  [note] %d excluded secret(s) not confirmed against a live --secrets-dir; "
        "restore depends on their out-of-band copies"
        % sum(1 for e in required if not e.get("included"))
    )

print("  [%s] control-plane DB integrity (" % ("ok" if cp_ok else "FAIL") + cp_state + ")")
print("  [%s] staging DB integrity (" % ("ok" if st_ok else "FAIL") + st_state + ")")
print(
    "  [ok] control-plane schema version %s / staging schema version %s"
    % (cp_have if cp_have is not None else "?", st_have if st_have is not None else "?")
)
for ident in sorted(e.get("id", "?") for e in required):
    print("  [ok] secret identifier accounted: %s" % ident)
print(
    "  [ok] deployment config present: %s"
    % (compose_rel if compose_rel in recorded else "MISSING")
)

if failures:
    print("\nVerification gaps:")
    for gap in failures:
        print("  - %s" % gap)
    sys.exit(1)
print("\nVerification passed: archive is complete, checksummed, and consistent.")
PY
if [ "$?" -ne 0 ]; then
  exit 1
fi

echo "verify-backup: PASS"
exit 0