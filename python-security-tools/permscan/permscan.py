#!/usr/bin/env python3
"""
permscan - Filesystem permission auditing CLI.

Walks a directory tree and flags files/directories with risky permission
bits set (world-writable, setuid, setgid), using os.stat and bitwise checks
against the `stat` module's mode constants.

Examples:
    permscan scan /var/www
    permscan scan /opt/app --no-recursive --json
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Iterator, NamedTuple

FLAG_BITS = {
    "world-writable": stat.S_IWOTH,
    "setuid": stat.S_ISUID,
    "setgid": stat.S_ISGID,
}


class Finding(NamedTuple):
    path: str
    octal: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"path": self.path, "permissions": self.octal, "reasons": list(self.reasons)}


def octal_perms(mode: int) -> str:
    """Return the permission bits of `mode` as an octal string.

    Ordinary permissions render as 3 digits, e.g. '644'. If setuid, setgid,
    or the sticky bit is set, a 4th leading digit is included, e.g. '4755'
    for a setuid binary -- that leading digit is exactly the security signal
    this scanner cares about, so it's never silently dropped.
    """
    perm = stat.S_IMODE(mode)  # 0..0o7777, includes setuid/setgid/sticky bits
    return format(perm, "03o") if perm <= 0o777 else format(perm, "04o")


def check_flags(mode: int, enabled_checks: set[str]) -> tuple[str, ...]:
    """Return the subset of `enabled_checks` whose bit is set in `mode`."""
    return tuple(name for name in enabled_checks if mode & FLAG_BITS[name])


def _check_path(path: Path, enabled_checks: set[str]) -> Finding | None:
    try:
        mode = path.lstat().st_mode  # lstat: don't follow symlinks
    except OSError:
        return None
    reasons = check_flags(mode, enabled_checks)
    if reasons:
        return Finding(path=str(path), octal=octal_perms(mode), reasons=reasons)
    return None


def scan(root: Path, recursive: bool = True, enabled_checks: set[str] | None = None) -> Iterator[Finding]:
    """Walk `root` and yield a Finding for every flagged file or directory."""
    checks = enabled_checks if enabled_checks is not None else set(FLAG_BITS)

    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                finding = _check_path(Path(dirpath) / name, checks)
                if finding:
                    yield finding
    else:
        for entry in root.iterdir():
            finding = _check_path(entry, checks)
            if finding:
                yield finding


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permscan",
        description="Audit filesystem permissions for risky bits (world-writable, setuid, setgid).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Scan a directory")
    scan_p.add_argument("directory", type=Path)
    scan_p.add_argument("--no-recursive", action="store_true", help="Only scan the top-level directory")
    scan_p.add_argument("--json", action="store_true", help="Output findings as JSON")
    scan_p.add_argument("--no-world-writable", action="store_true", help="Skip the world-writable check")
    scan_p.add_argument("--no-setuid", action="store_true", help="Skip the setuid check")
    scan_p.add_argument("--no-setgid", action="store_true", help="Skip the setgid check")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.directory.exists() or not args.directory.is_dir():
        print(f"error: not a directory: {args.directory}", file=sys.stderr)
        return 2

    enabled = set(FLAG_BITS)
    if args.no_world_writable:
        enabled.discard("world-writable")
    if args.no_setuid:
        enabled.discard("setuid")
    if args.no_setgid:
        enabled.discard("setgid")

    findings = list(scan(args.directory, recursive=not args.no_recursive, enabled_checks=enabled))

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No flagged permissions found under {args.directory}")
        for f in findings:
            print(f"{f.octal}  {f.path}  [{', '.join(f.reasons)}]")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
