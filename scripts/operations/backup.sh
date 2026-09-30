#!/usr/bin/env bash
# backup.sh — create a consistent, deterministic uncloud-registry backup (Task 26).
#
# What the archive contains:
#   manifest.json       machine-readable index (sorted keys, fixed schema tag)
#   SHA256SUMS          sorted SHA-256 checksums of every archived file
#   controlplane.db     consistent snapshot of the control-plane database
#                       (SQLite VACUUM INTO — transactional point-in-time copy)
#   staging.db          consistent snapshot of the staging database (same method)
#   spool.tar           deterministic archive of the staging spool directory
#                       (sidecar + payload files; sorted path list, owner-only)
#   compose.yaml        the deployment configuration at backup time (no secrets)
#   key-versions.json   key VERSION identifiers only (master-key current/loaded
#                       versions, registry-JWKS kid set) — never key bytes
#   EXCLUDED.list       identifiers of secrets deliberately NOT in the archive
#
# Secrets are NEVER copied into the unencrypted archive by default: the
# master key (master.json), the internal credential/key pair, the Bee
# keystore password, and the deployment .env (CONTROLPLANE_TOKEN_SECRET,
# CONTROLPLANE_REGISTRY_ED25519_KEY) are listed in EXCLUDED.list and must be
# restored out-of-band from the live secrets directory or your secret
# manager. `--include-master-key` is an explicit, discouraged opt-in
# documented in docs/operations/backup-restore.md.
#
# Deterministic: fixed file names, sorted file lists, sorted SHA256SUMS,
# sorted manifest keys. Idempotent: re-running with the same --label replaces
# nothing; use --force to rebuild an existing label.
#
# The script self-verifies by running verify-backup.sh on the fresh archive
# and refuses to report success on any gap.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# --- argument parsing -------------------------------------------------------

usage() {
  cat >&2 <<'EOF'
usage: backup.sh [options]

  --deploy-dir DIR     deployment root (default: current directory)
                       layout: <deploy>/compose.yaml, <deploy>/data/
                       {controlplane.db,staging.db,spool/}, <deploy>/secrets/
  --controlplane-db P  override control-plane database path
  --staging-db P       override staging database path
  --staging-root D     override staging spool root directory
  --compose-file P     override deployment config path (default: <deploy>/compose.yaml)
  --secrets-dir D      live secrets directory (default: <deploy>/secrets)
  --out DIR            backup parent directory (default: <deploy>/backups)
  --label NAME         backup label (default: uncloud-registry-backup-<UTC timestamp>)
  --include-master-key copy master.json INTO the unencrypted archive
                       (DISCOURAGED: only justified when the archive itself
                       is encrypted at rest by the transport/storage layer)
  --force              atomically rebuild an existing --label directory
  -h, --help           this help
EOF
}

DEPLOY_DIR="$(pwd)"
CONTROLPLANE_DB=""
STAGING_DB=""
STAGING_ROOT=""
COMPOSE_FILE=""
SECRETS_DIR=""
OUT_DIR=""
LABEL=""
INCLUDE_MASTER_KEY=0
FORCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --deploy-dir) DEPLOY_DIR="${2:-}"; shift 2 ;;
    --controlplane-db) CONTROLPLANE_DB="${2:-}"; shift 2 ;;
    --staging-db) STAGING_DB="${2:-}"; shift 2 ;;
    --staging-root) STAGING_ROOT="${2:-}"; shift 2 ;;
    --compose-file) COMPOSE_FILE="${2:-}"; shift 2 ;;
    --secrets-dir) SECRETS_DIR="${2:-}"; shift 2 ;;
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    --label) LABEL="${2:-}"; shift 2 ;;
    --include-master-key) INCLUDE_MASTER_KEY=1; shift ;;
    --force) FORCE=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

# --- resolve paths (defaults mirror the Task 24 compose layout) -------------
[ -n "$CONTROLPLANE_DB" ] || CONTROLPLANE_DB="$DEPLOY_DIR/data/controlplane.db"
[ -n "$STAGING_DB" ] || STAGING_DB="$DEPLOY_DIR/data/staging.db"
[ -n "$STAGING_ROOT" ] || STAGING_ROOT="$DEPLOY_DIR/data/spool"
[ -n "$COMPOSE_FILE" ] || COMPOSE_FILE="$DEPLOY_DIR/compose.yaml"
[ -n "$SECRETS_DIR" ] || SECRETS_DIR="$DEPLOY_DIR/secrets"
[ -n "$OUT_DIR" ] || OUT_DIR="$DEPLOY_DIR/backups"

for f in "$CONTROLPLANE_DB" "$STAGING_DB" "$COMPOSE_FILE"; do
  [ -f "$f" ] || { echo "error: required file missing: $f" >&2; exit 2; }
done
[ -d "$STAGING_ROOT" ] || { echo "error: staging root missing: $STAGING_ROOT" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 2; }
sha256of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

# --- label + staging + output -----------------------------------------------
if [ -z "$LABEL" ]; then
  LABEL="uncloud-registry-backup-$(date -u +%Y%m%dT%H%M%SZ)"
fi
BACKUP_DIR="$OUT_DIR/$LABEL"
if [ -e "$BACKUP_DIR" ]; then
  if [ "$FORCE" -eq 1 ]; then
    rm -rf "$BACKUP_DIR"
  else
    echo "error: backup label already exists (use --force to rebuild): $BACKUP_DIR" >&2
    exit 2
  fi
fi
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
BACKUP_DIR="$OUT_DIR/$LABEL"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/uncloud-backup.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

echo "Backup label: $LABEL"
echo "  control-plane DB : $CONTROLPLANE_DB"
echo "  staging DB       : $STAGING_DB"
echo "  staging root     : $STAGING_ROOT"
echo "  compose config   : $COMPOSE_FILE"
echo "  secrets dir      : $SECRETS_DIR"

# --- consistent SQLite snapshots (VACUUM INTO) ------------------------------
# VACUUM INTO is the SQLite online-backup mechanism: it produces a
# transactional point-in-time copy even while writers are active, and never
# disturbs the live database or its WAL. A PASSIVE WAL checkpoint first
# narrows the window the snapshot must read through; the snapshot itself is
# atomic regardless.
cp_sqlite_snapshot() {
  local src="$1" dst="$2"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$src" "pragma wal_checkpoint(PASSIVE);" >/dev/null 2>&1 || true
  fi
  python3 - "$src" "$dst" <<'PY'
import sqlite3
import sys

src, dst = sys.argv[1], sys.argv[2]
sql_dst = "'" + dst.replace("'", "''") + "'"
con = sqlite3.connect("file:%s?mode=ro" % src, uri=True)
try:
    con.execute("vacuum into %s" % sql_dst)
    con.commit()
finally:
    con.close()
PY
}

echo "Snapshotting control-plane database…"
cp_sqlite_snapshot "$CONTROLPLANE_DB" "$STAGE/controlplane.db"
echo "Snapshotting staging database…"
cp_sqlite_snapshot "$STAGING_DB" "$STAGE/staging.db"

# --- deterministic spool archive --------------------------------------------
# A sorted path list guarantees identical tar entry order across runs and
# machines. The list is generated in python3 (not shell find/grep) because
# OS sed/grep NUL handling is unreliable (e.g. BSD grep -z matches '\n' even
# when none exists) and the spool must reject ambiguous names. Filenames
# containing newlines are rejected; symlinks and special files are rejected
# (the spool is app-managed and holds only regular sidecar/payload files).
# Permissions and ownership are normalized to owner-only/root in the archive
# so restore is uniform on any host.
echo "Archiving staging spool…"
python3 - "$STAGING_ROOT" "$STAGE/spool.list" <<'PY'
import os
import sys

root, out_list = sys.argv[1], sys.argv[2]
entries = []
for dirpath, dirnames, filenames in os.walk(root):
    for name in dirnames + filenames:
        full = os.path.join(dirpath, name)
        rel = os.path.relpath(full, root)
        if rel == ".":
            continue
        if "\n" in rel:
            print("error: staging spool contains a filename with a newline; refusing to archive ambiguously", file=sys.stderr)
            sys.exit(2)
        if os.path.islink(full):
            print("error: staging spool contains a symlink; refusing: %s" % rel, file=sys.stderr)
            sys.exit(2)
        if not os.path.isfile(full) and not os.path.isdir(full):
            print("error: staging spool contains a non-regular, non-directory entry; refusing: %s" % rel, file=sys.stderr)
            sys.exit(2)
        entries.append(rel)
entries.sort()
with open(out_list, "w", encoding="utf-8") as f:
    for e in entries:
        f.write(e + "\n")
print("  %d spool entries" % len(entries))
PY
GNU_TAR=0
tar --version 2>/dev/null | grep -q GNU && GNU_TAR=1
if [ "$GNU_TAR" -eq 1 ]; then
  # GNU tar -T interprets backslash escapes; the spool names are byte-exact.
  # --uid/--gid/--mode only exist under GNU tar; restore.sh re-applies
  # owner-only modes from the manifest regardless of archive modes.
  (cd "$STAGING_ROOT" && tar -cf "$STAGE/spool.tar" --verbatim-files-from --uid=0 --gid=0 --mode=600 -T "$STAGE/spool.list")
else
  # bsdtar stores macOS resource-fork xattrs as AppleDouble '._' tar entries
  # by default; --no-xattrs keeps the archive to the real spool bytes only.
  (cd "$STAGING_ROOT" && tar -cf "$STAGE/spool.tar" --no-xattrs --uid=0 --gid=0 -T "$STAGE/spool.list")
fi
rm -f "$STAGE/spool.list"

# --- deployment configuration ------------------------------------------------
cp "$COMPOSE_FILE" "$STAGE/compose.yaml"

# --- key-version metadata (identifiers only, never key bytes) ----------------
python3 - "$STAGE" "$SECRETS_DIR" "$INCLUDE_MASTER_KEY" <<'PY'
import base64
import json
import os
import re
import sys

stage, secrets_dir, include_master = sys.argv[1], sys.argv[2], sys.argv[3] == "1"

# Master-key document: record ONLY version identifiers, never key values.
master_versions = {"current": None, "loaded": []}
master_path = os.path.join(secrets_dir, "master.json")
if os.path.isfile(master_path):
    with open(master_path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    try:
        master_versions["current"] = int(doc["current"])
    except Exception:  # noqa: BLE001 - recorded as unknown; verification fails
        master_versions["current"] = None
    for ver in doc.get("keys", {}):
        if re.match(r"^[1-9][0-9]*$", str(ver)):
            master_versions["loaded"].append(int(ver))
    master_versions["loaded"].sort()

# Registry-JWKS kid set: public identifiers only.
jwks_kids = []
jwks_path = os.path.join(secrets_dir, "registry-jwks.json")
if os.path.isfile(jwks_path):
    with open(jwks_path, "r", encoding="utf-8") as f:
        jwks = json.load(f)
    for entry in jwks.get("keys", []):
        kid = entry.get("kid")
        if kid not in (None, ""):
            jwks_kids.append(kid)
jwks_kids.sort()

with open(os.path.join(stage, "key-versions.json"), "w", encoding="utf-8") as f:
    json.dump(
        {
            "master_key_current_version": master_versions["current"],
            "master_key_loaded_versions": master_versions["loaded"],
            "registry_jwks_kids": jwks_kids,
        },
        f,
        indent=2,
        sort_keys=True,
    )
PY

# --- required-secrets accounting ---------------------------------------------
# Every identifier needed for a faithful restore. By default all of them are
# excluded from the unencrypted archive and restored out-of-band. When
# --include-master-key is given, ONLY master.json moves into the archive (it
# remains in the manifest so verification sees the accounting).
EXCLUDED_FILES="master.json
internal-secret.txt
internal-key.pem
registry-jwks.json
bee-password.txt"
MASTER_INCLUDED=0
if [ "$INCLUDE_MASTER_KEY" -eq 1 ]; then
  if [ ! -f "$SECRETS_DIR/master.json" ]; then
    echo "error: --include-master-key given but $SECRETS_DIR/master.json is missing" >&2
    exit 2
  fi
  cp "$SECRETS_DIR/master.json" "$STAGE/master.json"
  MASTER_INCLUDED=1
fi
: > "$STAGE/EXCLUDED.list"
for id in $EXCLUDED_FILES; do
  if [ "$id" = "master.json" ] && [ "$MASTER_INCLUDED" -eq 1 ]; then
    continue
  fi
  echo "$id" >> "$STAGE/EXCLUDED.list"
done
if [ -f "$DEPLOY_DIR/.env" ]; then
  echo ".env" >> "$STAGE/EXCLUDED.list"
fi

# --- state summary for the manifest ------------------------------------------
python3 - "$STAGE" <<'PY'
import json
import os
import sqlite3
import sys

stage = sys.argv[1]
summary = {}

def counts(con, tables):
    out = {}
    for table in tables:
        try:
            out[table] = con.execute("select count(*) from %s" % table).fetchone()[0]
        except Exception:  # noqa: BLE001 - table absent in this schema version
            out[table] = None
    return out

con = sqlite3.connect("file:%s/controlplane.db?mode=ro" % stage, uri=True)
try:
    summary.update(counts(con, (
        "users", "registries", "memberships", "registry_invites",
        "registry_publication_jobs", "publication_states",
    )))
    try:
        summary["controlplane_schema_version"] = con.execute(
            "select max(version) from schema_migrations"
        ).fetchone()[0]
    except Exception:  # noqa: BLE001
        summary["controlplane_schema_version"] = None
finally:
    con.close()

con = sqlite3.connect("file:%s/staging.db?mode=ro" % stage, uri=True)
try:
    summary.update(counts(con, ("upload_sessions", "staged_blobs")))
    try:
        summary["staging_schema_version"] = con.execute(
            "select max(version) from staging_schema"
        ).fetchone()[0]
    except Exception:  # noqa: BLE001
        summary["staging_schema_version"] = None
finally:
    con.close()

with open(os.path.join(stage, "state-summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
PY

# --- manifest ----------------------------------------------------------------
python3 - "$STAGE" "$LABEL" "$COMPOSE_FILE" <<'PY'
import json
import os
import sys

stage, label, compose_file = sys.argv[1], sys.argv[2], sys.argv[3]
with open(os.path.join(stage, "key-versions.json"), "r", encoding="utf-8") as f:
    key_versions = json.load(f)
with open(os.path.join(stage, "state-summary.json"), "r", encoding="utf-8") as f:
    state_summary = json.load(f)

compose_sha = None
try:
    import hashlib
    compose_sha = hashlib.sha256(open(compose_file, "rb").read()).hexdigest()
except Exception:  # noqa: BLE001
    pass

excluded = []
with open(os.path.join(stage, "EXCLUDED.list"), "r", encoding="utf-8") as f:
    for line in f.read().splitlines():
        if line.strip():
            excluded.append(line.strip())

master_included = os.path.isfile(os.path.join(stage, "master.json"))
required_secrets = [
    {
        "id": "master.json",
        "included": master_included,
        "file": "master.json" if master_included else None,
        "excluded_reason": None if master_included else
        "master key never enters an unencrypted backup by default; restore from secret manager or secure out-of-band copy",
    },
    {"id": "internal-secret.txt", "included": False, "file": None,
     "excluded_reason": "credential file; excluded from unencrypted archives; restore from live secrets dir or secret manager"},
    {"id": "internal-key.pem", "included": False, "file": None,
     "excluded_reason": "private key file; excluded from unencrypted archives; restore from live secrets dir or secret manager"},
    {"id": "registry-jwks.json", "included": False, "file": None,
     "excluded_reason": "credential-bearing JWKS holder file; excluded from unencrypted archives"},
    {"id": "bee-password.txt", "included": False, "file": None,
     "excluded_reason": "Bee keystore password; excluded from unencrypted archives"},
]

manifest = {
    "schema": "uncloud-registry-backup/v1",
    "label": label,
    "created_at": None,  # filled in by the shell after this pass
    "tool": "scripts/operations/backup.sh",
    "backup": {
        "controlplane_db": "controlplane.db",
        "staging_db": "staging.db",
        "spool_archive": "spool.tar",
        "compose_config": "compose.yaml",
        "key_version_metadata": "key-versions.json",
    },
    "files": [],  # filled below after the checksum pass sees every file
    "compose_config_sha256": compose_sha,
    "controlplane_schema_version": state_summary.get("controlplane_schema_version"),
    "staging_schema_version": state_summary.get("staging_schema_version"),
    "key_versions": key_versions,
    "state_summary": state_summary,
    "required_secrets": required_secrets,
    "excluded_from_archive": excluded,
}
with open(os.path.join(stage, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
PY

# --- checksums + final manifest ----------------------------------------------
(
  cd "$STAGE"
  # every file except the two index files themselves; re-run covers all files
  find . -type f ! -name SHA256SUMS ! -name manifest.json | LC_ALL=C sort \
    | while IFS= read -r f; do
        sha256of "$f"
      done
) | sed -E 's#^([0-9a-f]{64})  \./#\1  #' > "$STAGE/SHA256SUMS"

# created_at is the only non-deterministic field; the manifest files list is
# finalized after the checksum pass so both indexes agree.
python3 - "$STAGE" "$LABEL" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

stage = sys.argv[1]
path = os.path.join(stage, "manifest.json")
manifest = json.load(open(path, encoding="utf-8"))
files = []
for root, _dirs, names in os.walk(stage):
    for name in names:
        if name in ("SHA256SUMS",):
            continue  # the checksum index is its own authority, not a payload
        rel = os.path.relpath(os.path.join(root, name), stage)
        files.append(rel)
manifest["files"] = sorted(set(files))
manifest["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
PY

# --- publish + self-verify ---------------------------------------------------
# Final checksum pass covers manifest.json too (it changed in the finalize
# step); SHA256SUMS itself stays out of its own index.
(
  cd "$STAGE"
  find . -type f ! -name SHA256SUMS | LC_ALL=C sort \
    | while IFS= read -r f; do
        sha256of "$f"
      done
) | sed -E 's#^([0-9a-f]{64})  \./#\1  #' > "$STAGE/SHA256SUMS"

mkdir -p "$BACKUP_DIR"
(
  cd "$STAGE"
  find . -maxdepth 1 -mindepth 1 -exec mv {} "$BACKUP_DIR/" \;
)
chmod 0700 "$BACKUP_DIR"
chmod 0600 "$BACKUP_DIR/controlplane.db" "$BACKUP_DIR/staging.db"
if [ -f "$BACKUP_DIR/master.json" ]; then
  chmod 0600 "$BACKUP_DIR/master.json"
fi

echo ""
echo "Archive written to: $BACKUP_DIR"
echo "Self-verifying archive…"
VERIFY_ARGS=(--backup-dir "$BACKUP_DIR")
if [ -n "$SECRETS_DIR" ]; then
  VERIFY_ARGS+=(--secrets-dir "$SECRETS_DIR")
fi
if ! bash "$REPO_ROOT/scripts/operations/verify-backup.sh" "${VERIFY_ARGS[@]}"; then
  echo "error: backup failed self-verification; archive left at $BACKUP_DIR for inspection" >&2
  exit 1
fi
echo ""
echo "backup: PASS"
echo "  excluded secrets (restore out-of-band): $(tr '\n' ' ' < "$BACKUP_DIR/EXCLUDED.list")"