#!/usr/bin/env python3
"""KMN-CyberSeek version bumper.

Usage:
    python bump_version.py              # print the current version
    python bump_version.py 2.2.5        # set the version everywhere (code + README badge)

This edits only the version *number* in _version.py and the README badge. The
frontend and FastAPI backend read _version.py at runtime, so they update
automatically. The changelog entry text stays manual (its content differs every
release) — add a new `## [X.Y.Z] — DATE` section to change_log.md yourself.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
_VERSION_RE = re.compile(r'__version__\s*=\s*"([^"]+)"')
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+([-.].+)?$")


def read_version() -> str:
    text = (ROOT / "_version.py").read_text(encoding="utf-8")
    m = _VERSION_RE.search(text)
    if not m:
        raise SystemExit("Could not find __version__ in _version.py")
    return m.group(1)


def set_version(new: str) -> None:
    if not _SEMVER_RE.match(new):
        raise SystemExit(f"'{new}' is not a valid semantic version (e.g. 2.2.5)")

    # 1. _version.py — the source of truth the code reads.
    vp = ROOT / "_version.py"
    vp.write_text(
        _VERSION_RE.sub(f'__version__ = "{new}"', vp.read_text(encoding="utf-8"), count=1),
        encoding="utf-8",
    )

    # 2. README badge — static markdown, kept in sync here.
    rp = ROOT / "README.md"
    if rp.exists():
        rp.write_text(
            re.sub(r"Version-\d+\.\d+\.\d+(?:[-.][\w.]+)?-brightgreen",
                   f"Version-{new}-brightgreen", rp.read_text(encoding="utf-8")),
            encoding="utf-8",
        )

    print(f"Version set to {new} (updated _version.py + README badge).")
    print("Remember to add a change_log.md entry for this release.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(read_version())
    elif len(sys.argv) == 2:
        set_version(sys.argv[1])
    else:
        raise SystemExit("usage: python bump_version.py [X.Y.Z]")
