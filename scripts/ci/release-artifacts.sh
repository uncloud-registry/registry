#!/usr/bin/env bash
# Release artifact generation (scripts/ci/release-artifacts.sh) — Task 25.
#
# Produces, for a set of already-built binaries, deterministic SHA-256
# checksums and per-binary CycloneDX SBOMs. Called by the release workflow
# after `go build` has populated the distribution directory.
#
# Usage:
#   bash scripts/ci/release-artifacts.sh <out-dir> <binary> [<binary>...]
#
# Outputs (all written under <out-dir>):
#   checksums.txt      "<sha256>  <basename>" per input, sorted by name
#   <name>.cdx.json    CycloneDX SBOM per binary (via syft)
#
# Determinism: checksum entries are sorted by filename, the checksum text uses
# the standard two-column "<hex>  <name>" form, and syft output is byte-stable
# for identical binaries (it reads the embedded Go build metadata).
set -euo pipefail

usage() {
  echo "usage: $0 <out-dir> <binary> [<binary>...]" >&2
  exit 2
}

[ "$#" -ge 2 ] || usage

OUT_DIR="$1"; shift

[ "$#" -ge 1 ] || usage

mkdir -p "$OUT_DIR"

# Portable SHA-256: GNU coreutils `sha256sum` on Linux/CI, `shasum -a 256` on
# macOS. Emit only the hex digest (the file name is added in standard form).
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Validate every input before producing any output (fail-closed).
BINS=()
for b in "$@"; do
  [ -f "$b" ] || { echo "error: binary not found: $b" >&2; exit 1; }
  BINS+=("$b")
done

CHECKSUMS="$OUT_DIR/checksums.txt"
: > "$CHECKSUMS"
for b in "${BINS[@]}"; do
  printf '%s  %s\n' "$(sha256_hex "$b")" "$(basename "$b")" >> "$CHECKSUMS"
done
# Sort by filename so regeneration is byte-stable regardless of argument order.
sort -k2 "$CHECKSUMS" -o "$CHECKSUMS"

# SBOMs: syft is the SBOM generator and is installed by the release workflow.
if ! command -v syft >/dev/null 2>&1; then
  echo "error: syft is required for SBOM generation; the release workflow installs it" >&2
  exit 1
fi
for b in "${BINS[@]}"; do
  name="$(basename "$b")"
  syft "$b" -o "cyclonedx-json=$OUT_DIR/$name.cdx.json"
done

echo "release artifacts written under $OUT_DIR:"
for b in "${BINS[@]}"; do
  printf '  %s.cdx.json\n' "$(basename "$b")"
done
printf '  checksums.txt\n'
