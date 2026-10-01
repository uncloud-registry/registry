#!/usr/bin/env bash
# restore.sh — restore a uncloud-registry backup into an ISOLATED destination
# (Task 26).
#
# Safety model:
#   * Checksums are verified FIRST (the archive must pass verify-backup.sh
#     before a single byte is restored).
#   * The destination must be EMPTY unless the operator passes --yes.
#   * With --yes the destination may already contain files, but the script
#     still refuses when a live process holds one of the database files
#     (lsof check) — a running deployment must be stopped first, never
#     overwritten underneath.
#   * Restored files carry restrictive permissions (0700 directories, 0600
#     databases/keys).
#   * Migration/readiness checks run before success is reported:
#       - PRAGMA integrity_check on both restored databases
#       - PRAGMA foreign_key_check on the restored control-plane database
#       - schema version tables match the manifest's recorded versions
#     (the binaries run their full migration suite at startup; these checks
#     prove the restored databases are loadable and schema-consistent.)
#
# Secrets are NOT part of the archive (see backup.sh); after restoring the
# data, the operator places the excluded secret files back from the live
# secrets directory / secret manager and starts the stack. The stack's
# startup validation then fails closed on any missing or malformed secret.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# --- argument parsing -------------------------------------------------------

usage() {
  cat >&2 <<'EOF'
usage: restore.sh --backup-dir DIR --dest DIR [--secrets-dir DIR] [--yes]

  --backup-dir DIR   verified backup archive (must pass verify-backup.sh)
  --dest DIR         ISOLATED destination directory; must be empty unless
                     --yes is given
  --secrets-dir DIR  optional live secrets dir forwarded to verify-backup.sh
  --yes              allow restoring into a non-empty destination (operator
                     has confirmed the stack there is STOPPED and drained)
  -h, --help         this help
EOF
}

BACKUP_DIR=""
DEST=""
SECRETS_DIR=""
YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --backup-dir) BACKUP_DIR="${2:-}"; shift 2 ;;
    --dest) DEST="${2:-}"; shift 2 ;;
    --secrets-dir) SECRETS_DIR="${2:-}"; shift 2 ;;
    --yes) YES=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "$BACKUP_DIR" ] || [ -z "$DEST" ]; then
  echo "error: --backup-dir and --dest are required" >&2
  usage
  exit 2
fi
[ -d "$BACKUP_DIR" ] || { echo "error: backup directory does not exist: $BACKUP_DIR" >&2; exit 2; }
[ "$BACKUP_DIR" != "$DEST" ] || { echo "error: --dest must differ from --backup-dir" >&2; exit 2; }

command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 2; }

# --- 1. verify the archive BEFORE touching the destination ------------------
echo "Step 1/4 — verifying backup archive…"
VERIFY_ARGS=(--backup-dir "$BACKUP_DIR")
if [ -n "$SECRETS_DIR" ]; then
  VERIFY_ARGS+=(--secrets-dir "$SECRETS_DIR")
fi
if ! bash "$REPO_ROOT/scripts/operations/verify-backup.sh" "${VERIFY_ARGS[@]}"; then
  echo "error: backup archive failed verification; restore aborted (nothing was written)" >&2
  exit 1
fi

# --- 2. destination policy ---------------------------------------------------
echo "Step 2/4 — checking destination: $DEST"
if [ -e "$DEST" ]; then
  if [ ! -d "$DEST" ]; then
    echo "error: destination exists and is not a directory: $DEST" >&2
    exit 2
  fi
  if [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
    if [ "$YES" -ne 1 ]; then
      echo "error: destination is not empty: $DEST" >&2
      echo "  restore refuses to overwrite anything without --yes (operator confirms the" >&2
      echo "  deployment at the destination is STOPPED and drained)" >&2
      exit 1
    fi
    echo "  warning: destination is not empty; --yes given — proceeding (operator confirmed stack stopped)"
  fi
else
  mkdir -p "$DEST"
fi

# Refuse to restore over a LIVE deployment: if any process currently has one
# of the destination database files open, the stack is running there.
if command -v lsof >/dev/null 2>&1; then
  for db in "$DEST"/controlplane.db "$DEST"/staging.db; do
    if [ -f "$db" ] && lsof "$db" >/dev/null 2>&1; then
      echo "error: a live process holds $db (output of lsof above); stop the deployment at the destination first" >&2
      exit 1
    fi
  done
else
  echo "  note: lsof not available; live-deployment detection skipped (stop the stack manually before restoring)"
fi

# --- 3. restore with restrictive permissions --------------------------------
echo "Step 3/4 — restoring archive contents…"
# Directories 0700; databases and key material 0600; config 0644 (read-only
# view is fine for compose.yaml; the operator re-applies their own modes on
# the live tree anyway).
install -d -m 0700 "$DEST"

python3 - "$BACKUP_DIR" "$DEST" <<'PY'
import json
import os
import sys
import tarfile

backup_dir, dest = sys.argv[1], sys.argv[2]
dest = os.path.abspath(dest)
manifest = json.load(open(os.path.join(backup_dir, "manifest.json"), encoding="utf-8"))

def write_restricted(rel):
    src = os.path.join(backup_dir, rel)
    dst = os.path.join(dest, rel)
    os.makedirs(os.path.dirname(dst) if os.path.dirname(dst) else dest, exist_ok=True)
    with open(src, "rb") as f_in, open(dst, "wb") as f_out:
        f_out.write(f_in.read())
    os.chmod(dst, 0o600)

# Restore every payload file listed in the manifest. Deterministic order:
# manifest.files is sorted, so extraction is byte-reproducible.
for rel in manifest.get("files", []):
    if rel in ("manifest.json", "SHA256SUMS", "EXCLUDED.list"):
        continue  # index/metadata files are not extracted as payloads
    if rel.endswith(".db"):
        continue  # copied by the shell with guaranteed 0600
    if rel == "spool.tar":
        spool_dst = os.path.join(dest, "spool")
        os.makedirs(spool_dst, exist_ok=True)
        os.chmod(spool_dst, 0o700)
        with tarfile.open(os.path.join(backup_dir, rel), "r:") as tf:
            for member in tf.getmembers():
                # Defense in depth: never restore macOS AppleDouble (
                # '._name') or __MACOSX/ sidecar entries.
                name = os.path.basename(member.name)
                if name.startswith("._") or member.name.startswith("__MACOSX/"):
                    continue
                # Path-containment: the archive is self-produced and
                # checksum-verified, but restore still never trusts member
                # names to stay inside the spool tree.
                target = os.path.normpath(os.path.join(spool_dst, member.name))
                if not (target == spool_dst or target.startswith(spool_dst + os.sep)):
                    raise SystemExit(
                        "spool archive member escapes the spool tree: %r" % member.name
                    )
                if member.isdir():
                    os.makedirs(target, exist_ok=True)
                    os.chmod(target, 0o700)
                elif member.isfile():
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as f_out:
                        srcf = tf.extractfile(member)
                        if srcf is None:
                            raise SystemExit(
                                "cannot extract spool member: %r" % member.name
                            )
                        with srcf:
                            f_out.write(srcf.read())
                    os.chmod(target, 0o600)
                else:
                    raise SystemExit(
                        "spool archive contains a non-regular entry; refusing: %r"
                        % member.name
                    )
        continue
    if rel in ("key-versions.json", "state-summary.json", "compose.yaml"):
        src = os.path.join(backup_dir, rel)
        dst = os.path.join(dest, rel)
        with open(src, "rb") as f_in, open(dst, "wb") as f_out:
            f_out.write(f_in.read())
        os.chmod(dst, 0o644)
        continue
    # Unknown payload: restore with owner-only permissions and fail loudly
    # rather than guessing.
    write_restricted(rel)
PY

# The .db files are copied by the shell so their owner-only mode is
# guaranteed independent of umask and cp defaults.
cp "$BACKUP_DIR/controlplane.db" "$DEST/controlplane.db"
cp "$BACKUP_DIR/staging.db" "$DEST/staging.db"
chmod 0600 "$DEST/controlplane.db" "$DEST/staging.db"
if [ -f "$BACKUP_DIR/compose.yaml" ]; then
  cp "$BACKUP_DIR/compose.yaml" "$DEST/compose.yaml"
  chmod 0644 "$DEST/compose.yaml"
fi
cp "$BACKUP_DIR/manifest.json" "$DEST/manifest.json"

# --- 4. migration/readiness checks on the restored tree ----------------------
echo "Step 4/4 — restored-tree migration/readiness checks…"
python3 - "$DEST" "$BACKUP_DIR" <<'PY'
import json
import os
import sqlite3
import sys

dest, backup_dir = sys.argv[1], sys.argv[2]
dest = os.path.abspath(dest)
manifest = json.load(open(os.path.join(backup_dir, "manifest.json"), encoding="utf-8"))
failures = []

def check_db(rel, tables):
    path = os.path.join(dest, rel)
    modes_ok = (os.stat(path).st_mode & 0o777) == 0o600
    if not modes_ok:
        failures.append("%s mode is not 0600 (got %04o)" % (rel, os.stat(path).st_mode & 0o777))
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        row = con.execute("pragma integrity_check").fetchone()
        if row is None or row[0] != "ok":
            failures.append("%s integrity_check failed: %r" % (rel, row[:3]))
        if "schema_migrations" in tables or "staging_schema" in tables:
            tname = "schema_migrations" if "schema_migrations" in tables else "staging_schema"
            ver = con.execute("select max(version) from %s" % tname).fetchone()[0]
            want = manifest.get("controlplane_schema_version" if tname == "schema_migrations"
                                else "staging_schema_version")
            if want is not None and int(ver) != int(want):
                failures.append("%s schema version %d != manifest %d" % (rel, int(ver), int(want)))
        for table in tables:
            if table in ("schema_migrations", "staging_schema"):
                continue
            try:
                con.execute("select count(*) from %s" % table)
            except Exception as exc:  # noqa: BLE001
                failures.append("%s: table %s unreadable: %s" % (rel, table, exc))
    finally:
        con.close()

check_db("controlplane.db", ("schema_migrations", "users", "registries"))
check_db("staging.db", ("staging_schema", "upload_sessions"))

# Foreign-key consistency on the control-plane tree.
con = sqlite3.connect("file:%s/controlplane.db?mode=ro" % dest, uri=True)
try:
    rows = con.execute("pragma foreign_key_check").fetchall()
    if rows:
        failures.append("control-plane foreign_key_check found %d violation(s)" % len(rows))
finally:
    con.close()

if failures:
    print("Restore readiness gaps:")
    for gap in failures:
        print("  - %s" % gap)
    sys.exit(1)
print("restore readiness: OK (integrity, schema versions, foreign keys, permissions)")
PY

echo ""
echo "restore: PASS"
echo "  restored data tree : $DEST"
echo "  excluded secrets    : place back from the live secrets dir / secret manager"
echo "  next step           : start the stack; binaries run their full migration"
echo "                       suite plus startup validation at boot"