#!/usr/bin/env python3
"""
hashcheck - File integrity verification CLI.

Computes and verifies cryptographic hashes of files using fixed-size
chunked reads, so it stays memory-safe on files far larger than RAM.

Examples:
    hashcheck compute myfile.iso --algo sha256
    hashcheck verify myfile.iso --hash 9f86d0... --algo sha256
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

CHUNK_SIZE = 65536  # 64KB
SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


def compute_hash(filepath: Path, algorithm: str = "sha256", chunk_size: int = CHUNK_SIZE) -> str:
    """Compute the hex digest of a file by reading it in fixed-size chunks.

    Args:
        filepath: Path to the file to hash.
        algorithm: One of SUPPORTED_ALGORITHMS.
        chunk_size: Bytes read per iteration.

    Returns:
        The lowercase hex digest string.

    Raises:
        ValueError: If algorithm is not supported.
        FileNotFoundError: If filepath does not exist.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. Choose from: {', '.join(SUPPORTED_ALGORITHMS)}"
        )

    hasher = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_hash(filepath: Path, expected_hash: str, algorithm: str = "sha256") -> tuple[bool, str]:
    """Verify a file's hash against an expected value.

    Returns:
        A (matched, actual_hash) tuple.
    """
    actual = compute_hash(filepath, algorithm)
    return actual.lower() == expected_hash.strip().lower(), actual


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashcheck",
        description="Compute or verify file hashes for integrity checking.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    compute_p = subparsers.add_parser("compute", help="Compute the hash of a file")
    compute_p.add_argument("file", type=Path, help="Path to the file")
    compute_p.add_argument("--algo", choices=SUPPORTED_ALGORITHMS, default="sha256")

    verify_p = subparsers.add_parser("verify", help="Verify a file against an expected hash")
    verify_p.add_argument("file", type=Path, help="Path to the file")
    verify_p.add_argument("--hash", required=True, dest="expected_hash", help="Expected hex digest")
    verify_p.add_argument("--algo", choices=SUPPORTED_ALGORITHMS, default="sha256")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.file.exists():
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 2
    if not args.file.is_file():
        print(f"error: not a regular file: {args.file}", file=sys.stderr)
        return 2

    try:
        if args.command == "compute":
            digest = compute_hash(args.file, args.algo)
            print(f"{args.algo}  {digest}  {args.file}")
            return 0

        if args.command == "verify":
            matched, actual = verify_hash(args.file, args.expected_hash, args.algo)
            if matched:
                print(f"OK: {args.file} matches expected {args.algo} hash")
                return 0
            print(f"MISMATCH: {args.file}")
            print(f"  expected: {args.expected_hash}")
            print(f"  actual:   {actual}")
            return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
