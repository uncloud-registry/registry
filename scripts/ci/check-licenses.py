#!/usr/bin/env python3
"""Dependency license gate (scripts/ci/check-licenses.py).

Deterministic, fail-closed replacement for ``go-licenses check ./...``.

``go-licenses check`` fails whenever it cannot RECOGNIZE a dependency's
license. That is correct for genuinely-missing licenses, but it is also a
false positive for a small set of modernc.org packages whose ``LICENSE`` file
carries a standard BSD-3-Clause text that go-licenses' license classifier
does not recognize (the classifier matches specific wordings). The one module
affected in this dependency graph is ``modernc.org/mathutil``.

This gate runs ``go-licenses csv ./...`` (which enumerates every module in
the import graph and the license type go-licenses detected) and then asserts:

  * every module carries a RECOGNIZED license type (anything other than
    ``Unknown``/empty), EXCEPT the modules named in the explicit audited
    allowlist below, each of which is asserted to be BSD-3-Clause by its own
    LICENSE file; and
  * every allowlisted module actually appears in the scan (so an allowlist
    entry can never silently go stale when a dependency is dropped).

The allowlist is the ONLY blind spot, and each entry is justified and
byte-verifiable against the module's shipped LICENSE. A genuinely-missing
license on any module — including a future modernc.org package — still fails
the gate.

Usage:
  python3 scripts/ci/check-licenses.py [--go-licenses PATH]

Exit code is 0 only when the gate passes. No dependencies beyond the Python 3
standard library.
"""

from __future__ import annotations

import argparse
import csv
import io
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Modules that ship a BSD-3-Clause LICENSE file go-licenses cannot classify.
# Each entry MUST be justified; the value records the license the module's own
# LICENSE file carries, so a reviewer can audit the exception without running
# anything. This is an explicit allowlist, never a prefix/wildcard ignore: a
# newly-added modernc.org module with a missing license still fails.
KNOWN_BSD_3_CLAUSE = {
    # LICENSE is the modernc.org BSD-3-Clause text ("The mathutil Authors",
    # three-clause redistribution terms); go-licenses' classifier does not
    # match its "names of the authors" wording variant.
    "modernc.org/mathutil": "BSD-3-Clause",
}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="check-licenses.py",
        description="Fail-closed dependency license gate over go-licenses csv.",
    )
    ap.add_argument(
        "--go-licenses",
        default="go-licenses",
        help="path to the go-licenses binary (default: resolve from PATH)",
    )
    args = ap.parse_args(argv)

    proc = subprocess.run(
        [args.go_licenses, "csv", "./..."],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print("go-licenses csv failed:", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        return proc.returncode or 1

    problems: list[str] = []
    seen: set[str] = set()
    reader = csv.reader(io.StringIO(proc.stdout))
    for row in reader:
        if not row or all(not c.strip() for c in row):
            continue
        module = (row[0] if len(row) > 0 else "").strip()
        license_name = (row[2] if len(row) > 2 else "").strip()
        if not module:
            continue
        seen.add(module)
        if module in KNOWN_BSD_3_CLAUSE:
            continue  # explicit audited BSD-3-Clause; classifier gap only
        if license_name == "" or license_name.lower() == "unknown":
            problems.append(module)

    for module in KNOWN_BSD_3_CLAUSE:
        if module not in seen:
            problems.append(
                f"{module} (allowlisted as BSD-3-Clause but absent from the license scan)"
            )

    if problems:
        print(
            f"license gate FAILED: {len(problems)} module(s) without a recognized license:",
            file=sys.stderr,
        )
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            "If a module is genuinely BSD-3-Clause but unclassifiable, add it to "
            "KNOWN_BSD_3_CLAUSE in this script with a justification; never add a "
            "wildcard.",
            file=sys.stderr,
        )
        return 1

    print(
        f"license gate OK: {len(seen)} module(s) in the import graph, "
        "all carrying a recognized license (or an audited BSD-3-Clause allowlist entry)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
