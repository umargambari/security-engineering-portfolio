#!/usr/bin/env python3
"""Encoding Toolkit — encode, decode, and detect string encodings."""

import argparse
import base64
import binascii
import codecs
import re
import sys
import urllib.parse


def encode_base64(text: str) -> str:
    """Encode a string to Base64."""
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def decode_base64(text: str) -> str:
    """Decode a Base64 string."""
    try:
        return base64.b64decode(text).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid Base64 input: {e}")


def encode_hex(text: str) -> str:
    """Encode a string to hexadecimal."""
    return text.encode("utf-8").hex()


def decode_hex(text: str) -> str:
    """Decode a hexadecimal string."""
    try:
        return bytes.fromhex(text).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid hex input: {e}")


def encode_url(text: str) -> str:
    """URL-encode a string."""
    return urllib.parse.quote(text)


def decode_url(text: str) -> str:
    """Decode a URL-encoded string."""
    return urllib.parse.unquote(text)


def encode_rot13(text: str) -> str:
    """Apply ROT13 encoding to a string."""
    return codecs.encode(text, "rot_13")


def detect_encoding(text: str) -> str:
    """Guess the encoding of a given string.

    Args:
        text: The encoded string to analyse.

    Returns:
        Best guess of the encoding: 'base64', 'hex', 'url', or 'unknown'.
    """
    if not text:
        return "unknown"

    if len(text) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in text):
        return "hex"

    if re.search(r"%[0-9A-Fa-f]{2}", text):
        return "url"

    base64_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    if all(c in base64_charset for c in text) and len(text) % 4 == 0:
        return "base64"

    return "unknown"


def cmd_encode(args: argparse.Namespace) -> None:
    """Handle the 'encode' subcommand."""
    encoders = {
        "base64": encode_base64,
        "hex": encode_hex,
        "url": encode_url,
        "rot13": encode_rot13,
    }
    result = encoders[args.format](args.text)
    print(result)


def cmd_decode(args: argparse.Namespace) -> None:
    """Handle the 'decode' subcommand."""
    decoders = {
        "base64": decode_base64,
        "hex": decode_hex,
        "url": decode_url,
        "rot13": encode_rot13,
    }
    try:
        result = decoders[args.format](args.text)
        print(result)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_detect(args: argparse.Namespace) -> None:
    """Handle the 'detect' subcommand."""
    guess = detect_encoding(args.text)
    print(f"Detected encoding: {guess}")

    if guess == "unknown":
        return

    decoders = {
        "base64": decode_base64,
        "hex": decode_hex,
        "url": decode_url,
    }
    try:
        decoded = decoders[guess](args.text)
        print(f"Decoded: {decoded}")
    except ValueError as e:
        print(f"Could not decode: {e}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="encoding",
        description="Encode, decode, and detect string encodings.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encode_parser = subparsers.add_parser("encode", help="Encode a string")
    encode_parser.add_argument("text", help="String to encode")
    encode_parser.add_argument(
        "--format", "-f", required=True,
        choices=["base64", "hex", "url", "rot13"],
        help="Encoding format",
    )
    encode_parser.set_defaults(func=cmd_encode)

    decode_parser = subparsers.add_parser("decode", help="Decode a string")
    decode_parser.add_argument("text", help="String to decode")
    decode_parser.add_argument(
        "--format", "-f", required=True,
        choices=["base64", "hex", "url", "rot13"],
        help="Encoding format",
    )
    decode_parser.set_defaults(func=cmd_decode)

    detect_parser = subparsers.add_parser("detect", help="Detect the encoding of a string")
    detect_parser.add_argument("text", help="Encoded string to analyse")
    detect_parser.set_defaults(func=cmd_detect)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
