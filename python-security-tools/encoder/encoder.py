#!/usr/bin/env python3
"""
encoder - Multi-scheme encode/decode CLI with auto-detection.

Supports base64, hex, URL, and ROT13. The `detect` command inspects an
input string and guesses which of those schemes (if any) it's encoded in,
using character-set patterns and a simple English-likelihood heuristic
for the ambiguous ROT13/base64 cases.

Examples:
    encoder encode --scheme base64 "hello world"
    encoder decode --scheme base64 "aGVsbG8gd29ybGQ="
    encoder detect "aGVsbG8gd29ybGQ="
"""

from __future__ import annotations

import argparse
import base64
import codecs
import re
import sys
import urllib.parse

SCHEMES = ("base64", "hex", "url", "rot13")

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_URL_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
_COMMON_ENGLISH_LETTERS = set("etaoinshrdlu")


def encode(text: str, scheme: str) -> str:
    if scheme == "base64":
        return base64.b64encode(text.encode()).decode()
    if scheme == "hex":
        return text.encode().hex()
    if scheme == "url":
        return urllib.parse.quote(text)
    if scheme == "rot13":
        return codecs.encode(text, "rot_13")
    raise ValueError(f"Unsupported scheme '{scheme}'. Choose from: {', '.join(SCHEMES)}")


def decode(text: str, scheme: str) -> str:
    if scheme == "base64":
        padded = text + "=" * (-len(text) % 4)
        return base64.b64decode(padded).decode(errors="replace")
    if scheme == "hex":
        return bytes.fromhex(text).decode(errors="replace")
    if scheme == "url":
        return urllib.parse.unquote(text)
    if scheme == "rot13":
        return codecs.encode(text, "rot_13")  # ROT13 is its own inverse
    raise ValueError(f"Unsupported scheme '{scheme}'. Choose from: {', '.join(SCHEMES)}")


def _english_score(s: str) -> int:
    """Rough heuristic: count of common English letters, case-insensitive."""
    return sum(1 for c in s.lower() if c in _COMMON_ENGLISH_LETTERS)


def detect(text: str) -> list[tuple[str, str]]:
    """Guess which scheme(s) `text` might be encoded in.

    Returns a list of (scheme, confidence) tuples, most likely first.
    Confidence is one of 'high', 'medium', 'low'.
    """
    guesses: list[tuple[str, str]] = []

    if _URL_ESCAPE_RE.search(text):
        guesses.append(("url", "high"))

    if text and _HEX_RE.match(text) and len(text) % 2 == 0:
        try:
            decoded_bytes = bytes.fromhex(text)
            ratio = sum(1 for b in decoded_bytes if 32 <= b < 127) / max(len(decoded_bytes), 1)
            guesses.append(("hex", "high" if ratio > 0.85 else "low"))
        except ValueError:
            pass

    if text and _BASE64_RE.match(text) and len(text) % 4 == 0:
        try:
            decoded_bytes = base64.b64decode(text, validate=True)
            ratio = sum(1 for b in decoded_bytes if 32 <= b < 127) / max(len(decoded_bytes), 1)
            guesses.append(("base64", "high" if ratio > 0.85 else "low"))
        except Exception:
            pass

    if text and all(c.isalpha() or c.isspace() for c in text) and any(c.isalpha() for c in text):
        rotated = codecs.encode(text, "rot_13")
        if _english_score(rotated) > _english_score(text):
            guesses.append(("rot13", "medium"))

    guesses.sort(key=lambda g: {"high": 0, "medium": 1, "low": 2}[g[1]])
    return guesses


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="encoder",
        description="Encode, decode, or auto-detect common text encodings.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc_p = subparsers.add_parser("encode", help="Encode text")
    enc_p.add_argument("text")
    enc_p.add_argument("--scheme", choices=SCHEMES, required=True)

    dec_p = subparsers.add_parser("decode", help="Decode text")
    dec_p.add_argument("text")
    dec_p.add_argument("--scheme", choices=SCHEMES, required=True)

    det_p = subparsers.add_parser("detect", help="Guess the encoding scheme of text")
    det_p.add_argument("text")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "encode":
            print(encode(args.text, args.scheme))
            return 0
        if args.command == "decode":
            print(decode(args.text, args.scheme))
            return 0
        if args.command == "detect":
            guesses = detect(args.text)
            if not guesses:
                print("No confident encoding guesses.")
                return 1
            for scheme, confidence in guesses:
                print(f"{scheme}  (confidence: {confidence})")
            return 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
