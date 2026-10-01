#!/usr/bin/env python3
"""PRD traceability checker for Uncloud Registry v1 (scripts/ci/check-prd-traceability.py).

Deterministically verifies that the release evidence index
(docs/evidence/release-index.json) maps EVERY requirement and audit-finding ID
declared in the PRD EXACTLY ONCE, with a valid status and the required fields,
and that no entry in the index refers to an ID the PRD does not declare.

IDs are parsed straight from the PRD source, not hardcoded:

  * requirement IDs  — ``### SEC-001:`` … ``### PERF-004:`` section headers
    (prefixes SEC, STAMP, PUB, STAGE, COMP, CP, OPS, PERF, AC);
  * audit-finding IDs — the ``| AUD-001 | …`` rows of the §20 audit matrix.

A release index entry must carry:

  * ``id``           — one of the IDs parsed from the PRD;
  * ``commit``       — short SHA of the implementing commit (non-empty);
  * ``test_command`` — the verifying command (non-empty);
  * ``evidence``     — the evidence file(s) backing the mapping (non-empty);
  * ``status``       — one of the four statuses below.

Status vocabulary (``implemented`` / ``accepted-carryover`` / ``deferred`` /
``deferred-phase4``):

  * ``implemented``       — merged and verified by deterministic tests that run
                           without a real Bee full node (unit / race / conformance
                           / real-SQLite backup-restore drill).
  * ``accepted-carryover`` — a reasoned, recorded ruling that the item is
                           non-load-bearing (see docs/evidence/v1-release-carryovers.md).
  * ``deferred``          — out of v1 release scope for an unrelated reason.
  * ``deferred-phase4``   — the code is implemented, but the requirement's
                           acceptance is a real-Bee feed round-trip or a real
                           Docker/Podman client E2E that is blocked pending a Bee
                           full node (docs/compatibility.md §8).

``deferred-phase4`` is accepted ONLY for the IDs below — the set that is
genuinely Bee-E2E-blocked. Marking any other ID ``deferred-phase4`` is rejected
so that the index cannot silently defer a requirement whose evidence is
producible today.

Bee-E2E-blocked allowlist (reason for each):

  * AC-006   — first push → generation one published *and pullable* against real Bee (Phase 2 gate).
  * AC-014   — real Docker client multi-platform index round trip (Phase 4 gate).
  * COMP-006 — pinned Docker/Podman client versions verified by an end-to-end push+pull (Phase 4 gate).
  * PERF-002 — Compose reference workload (small + ≥1 GiB layer + multi-platform) push/pull (Phase 5 E2E).
  * PERF-003 — p95 latency target measured on the running reference environment (needs a live real-Bee stack).
  * AUD-020  — "no real Bee or Docker end-to-end gate": the CI jobs exist but cannot execute until a full node is available.

Exit code is 0 only when the index is complete (no gaps, no duplicates, no
unknown IDs, valid statuses, ``deferred-phase4`` confined to the allowlist).
Any violation prints a diagnostic and exits non-zero.

Usage:
  python3 scripts/ci/check-prd-traceability.py [--prd PATH] [--index PATH]
  python3 scripts/ci/check-prd-traceability.py --render docs/evidence/v1-release-index.md
  python3 scripts/ci/check-prd-traceability.py --help

No dependencies beyond the Python 3 standard library.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# --- paths (relative to this script, i.e. the repository root) ---------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_PRD = REPO_ROOT / "docs" / "superpowers" / "specs" / \
    "2026-09-16-uncloud-registry-v1-completion-design.md"
DEFAULT_INDEX = REPO_ROOT / "docs" / "evidence" / "release-index.json"
DEFAULT_RENDER = REPO_ROOT / "docs" / "evidence" / "v1-release-index.md"

# --- constants ----------------------------------------------------------------

# Requirement section header: "### SEC-001: title"
_REQ_PREFIXES = ("SEC", "STAMP", "PUB", "STAGE", "COMP", "CP", "OPS", "PERF", "AC")
_REQ_RE = re.compile(r"^###\s+(?P<id>(?:%s)-\d{3}):" % "|".join(_REQ_PREFIXES))
# Audit matrix row: "| AUD-001 | … |"
_AUDIT_RE = re.compile(r"^\|\s*(?P<id>AUD-\d{3})\s*\|")

VALID_STATUSES = {"implemented", "accepted-carryover", "deferred", "deferred-phase4"}

# IDs whose acceptance is a real-Bee feed round-trip or a real Docker/Podman
# client E2E, and are therefore the ONLY ids allowed to carry deferred-phase4.
BEE_E2E_DEFERRED = {
    "AC-006": "first push must publish generation one and be pullable against real Bee",
    "AC-014": "real Docker client multi-platform index round trip",
    "COMP-006": "pinned Docker/Podman client versions need a successful end-to-end push+pull",
    "PERF-002": "Compose reference workload (small + 1 GiB layer + multi-platform) push/pull",
    "PERF-003": "p95 latency measured on the running reference environment",
    "AUD-020": "no real Bee/Docker end-to-end gate (CI jobs exist, blocked pending full node)",
}


# --- parsing ------------------------------------------------------------------

def parse_prd(path: Path) -> tuple[set[str], set[str]]:
    """Return (requirement_ids, audit_ids) parsed from the PRD source."""
    reqs: set[str] = set()
    audits: set[str] = set()
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        m = _REQ_RE.match(line)
        if m:
            reqs.add(m.group("id"))
            continue
        m = _AUDIT_RE.match(line)
        if m:
            audits.add(m.group("id"))
    return reqs, audits


def load_index(path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8")
    # json.load collapses duplicate keys; parse once to check for duplicate ids
    # structurally, but a list of entries makes duplicates explicit anyway.
    doc = json.loads(raw)
    entries = doc.get("entries")
    if not isinstance(entries, list):
        raise SystemExit(f"error: index {path} has no 'entries' list")
    return entries


# --- validation ---------------------------------------------------------------

def validate(reqs: set[str], audits: set[str], entries: list[dict]) -> int:
    expected = reqs | audits
    problems: list[str] = []

    seen: dict[str, int] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(f"entry {i}: not an object")
            continue
        eid = entry.get("id")
        if not eid:
            problems.append(f"entry {i}: missing 'id'")
            continue
        if eid not in expected:
            problems.append(f"entry {i}: id {eid!r} is not declared in the PRD")
            continue
        seen[eid] = seen.get(eid, 0) + 1

        for field in ("commit", "test_command", "evidence", "status"):
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"entry {i} ({eid}): missing/empty '{field}'")

        status = entry.get("status")
        if status not in VALID_STATUSES:
            problems.append(
                f"entry {i} ({eid}): invalid status {status!r} "
                f"(allowed: {sorted(VALID_STATUSES)})")
            continue
        if status == "deferred-phase4" and eid not in BEE_E2E_DEFERRED:
            problems.append(
                f"entry {i} ({eid}): 'deferred-phase4' is only valid for the "
                f"Bee-E2E-blocked IDs {sorted(BEE_E2E_DEFERRED)}")

    for eid, count in seen.items():
        if count > 1:
            problems.append(f"id {eid}: appears {count} times (duplicate)")

    missing = sorted(expected - set(seen))
    for eid in missing:
        problems.append(f"id {eid}: missing from the release evidence index (gap)")

    if not problems:
        print(
            f"OK: {len(expected)} PRD IDs parsed "
            f"({len(reqs)} requirements + {len(audits)} audit findings), "
            f"{len(entries)} index entries, all mapped exactly once.")
        deferred = [e["id"] for e in entries if e.get("status") == "deferred-phase4"]
        print(f"    deferred-phase4: {len(deferred)} ({', '.join(sorted(deferred))})")
        return 0

    print(f"FAIL: {len(problems)} traceability problem(s):", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    print(
        f"(expected {len(reqs)} requirements + {len(audits)} audit findings = "
        f"{len(expected)} IDs; index has {len(entries)} entries)",
        file=sys.stderr)
    return 1


# --- rendering (keep the human-readable table in sync with the JSON) ----------

def render_markdown(entries: list[dict], out: Path) -> None:
    statuses = sorted({e.get("status", "") for e in entries})
    lines: list[str] = []
    lines.append("# v1 release evidence index (rendered)")
    lines.append("")
    lines.append("> Generated by `scripts/ci/check-prd-traceability.py --render` from")
    lines.append("> `docs/evidence/release-index.json` (authoritative). Do not edit by hand;")
    lines.append("> regenerate after changing the JSON.")
    lines.append("")
    lines.append("| ID | Status | Commit | Evidence |")
    lines.append("|---|--------|--------|----------|")
    for e in sorted(entries, key=lambda x: x.get("id", "")):
        lines.append(
            f"| {e['id']} | {e['status']} | `{e['commit']}` | {e['evidence']} |")
    lines.append("")
    lines.append(f"Statuses present: {', '.join(statuses)}.")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"rendered {len(entries)} entries to {out}")


# --- main ---------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="check-prd-traceability.py",
        description="Verify every PRD requirement and audit ID maps exactly once "
                    "in the release evidence index.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--prd", type=Path, default=DEFAULT_PRD,
                    help="path to the PRD markdown (default: %(default)s)")
    ap.add_argument("--index", type=Path, default=DEFAULT_INDEX,
                    help="path to the release evidence JSON (default: %(default)s)")
    ap.add_argument("--render", type=Path, default=None, metavar="PATH",
                    help="regenerate the human-readable markdown index and exit")
    args = ap.parse_args(argv)

    if not args.prd.is_file():
        print(f"error: PRD not found: {args.prd}", file=sys.stderr)
        return 2
    if not args.index.is_file():
        print(f"error: release evidence index not found: {args.index}", file=sys.stderr)
        return 2

    reqs, audits = parse_prd(args.prd)
    if not reqs:
        print(f"error: no requirement IDs parsed from {args.prd}", file=sys.stderr)
        return 2
    if not audits:
        print(f"error: no audit-finding IDs parsed from {args.prd}", file=sys.stderr)
        return 2

    entries = load_index(args.index)

    if args.render is not None:
        render_markdown(entries, args.render)
        return 0

    return validate(reqs, audits, entries)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
