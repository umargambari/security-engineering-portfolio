#!/usr/bin/env python3
"""Permission Scanner — find files with overly permissive access rights."""
import argparse
import os
import stat
import sys


def get_permission_string(mode: int) -> str:
    """Convert a file mode to a human-readable permission string (e.g. rwxr-xr--)."""
    # Longhand version (kept for reference — one explicit check per bit):
    #
    # perms = ""
    # perms += "r" if mode & stat.S_IRUSR else "-"
    # perms += "w" if mode & stat.S_IWUSR else "-"
    # perms += "x" if mode & stat.S_IXUSR else "-"
    # perms += "r" if mode & stat.S_IRGRP else "-"
    # perms += "w" if mode & stat.S_IWGRP else "-"
    # perms += "x" if mode & stat.S_IXGRP else "-"
    # perms += "r" if mode & stat.S_IROTH else "-"
    # perms += "w" if mode & stat.S_IWOTH else "-"
    # perms += "x" if mode & stat.S_IXOTH else "-"
    # return perms

    perms = ""
    for who in ("USR", "GRP", "OTH"):
        for what, letter in (("R", "r"), ("W", "w"), ("X", "x")):
            mask = getattr(stat, f"S_I{what}{who}")
            perms += letter if mode & mask else "-"
    return perms


def is_world_readable(mode: int) -> bool:
    """Check if a file is world-readable."""
    return bool(mode & stat.S_IROTH)


def is_world_writable(mode: int) -> bool:
    """Check if a file is world-writable."""
    return bool(mode & stat.S_IWOTH)


def is_suid(mode: int) -> bool:
    """Check if a file has the SUID bit set."""
    return bool(mode & stat.S_ISUID)


def is_sgid(mode: int) -> bool:
    """Check if a file has the SGID bit set."""
    return bool(mode & stat.S_ISGID)


def scan_directory(path: str, filter_type: str | None = None, verbose: bool = False) -> list[dict]:
    """Walk a directory tree and find files with permission issues.

    If verbose is True, files with no issues are included too (issues will be []).
    """
    findings = []
    for root, dirs, files in os.walk(path):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                mode = os.stat(filepath).st_mode
            except (FileNotFoundError, PermissionError):
                continue

            issues = []
            if is_world_readable(mode):
                issues.append("world-readable")
            if is_world_writable(mode):
                issues.append("world-writable")
            if is_suid(mode):
                issues.append("suid")
            if is_sgid(mode):
                issues.append("sgid")

            if filter_type and filter_type not in issues:
                continue
            if not filter_type and not issues and not verbose:
                continue

            findings.append({
                "path": filepath,
                "permissions": get_permission_string(mode),
                "issues": issues,
            })
    return findings


def cmd_scan(args: argparse.Namespace) -> None:
    """Handle the 'scan' subcommand."""
    try:
        findings = scan_directory(args.path, args.filter, args.verbose)
    except PermissionError:
        print(f"Permission denied reading directory: {args.path}", file=sys.stderr)
        sys.exit(1)

    if not findings:
        print(f"No permission issues found in {args.path}.")
        return

    print(f"{'PATH':<50} {'PERMS':<12} ISSUES")
    for finding in findings:
        issues_str = ", ".join(finding["issues"]) if finding["issues"] else "-"
        print(f"{finding['path']:<50} {finding['permissions']:<12} {issues_str}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permscan",
        description="Scan directories for overly permissive file access rights.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan a directory for permission issues")
    scan_parser.add_argument("path", help="Directory to scan")
    scan_parser.add_argument(
        "--filter", "-f",
        choices=["world-readable", "world-writable", "suid", "sgid"],
        help="Only show files matching this issue type",
    )
    scan_parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show all files, not just those with issues",
    )
    scan_parser.set_defaults(func=cmd_scan)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
