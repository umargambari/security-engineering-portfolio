# Encoding Toolkit

A CLI tool that encodes and decodes strings between Base64, hex, URL encoding, and ROT13. The Swiss army knife you'll reach for constantly when analysing logs, deobfuscating payloads, or solving CTF challenges.

## Why this matters

Attackers encode payloads to evade detection. Logs contain URL-encoded data. Malware uses Base64 to hide command-and-control URLs. If you can't recognise and decode these encodings on sight, you'll miss things. This project builds that muscle memory.

## What you'll build

- Encode and decode strings in Base64, hex, URL encoding, and ROT13
- Auto-detect the encoding of an input string
- Chain multiple decode operations together

## Skills you'll prove

- Python standard library (`base64`, `binascii`, `urllib.parse`, `codecs`)
- String encoding and byte handling
- CLI design with argparse subcommands
- Input validation and error handling

## Getting started

```bash
make install
python src/main.py --help
```

## Commands

| Command | Description |
|---------|-------------|
| `encode` | Encode a string in a specified format |
| `decode` | Decode a string from a specified format |
| `detect` | Guess the encoding of a given string |

## Example usage

```bash
# Encode to Base64
python src/main.py encode "hello world" --format base64

# Decode from hex
python src/main.py decode "68656c6c6f" --format hex

# Auto-detect encoding
python src/main.py detect "aGVsbG8gd29ybGQ="
```

## Stretch goals

- Chain encodings (e.g. Base64 decode then URL decode)
- Read from stdin for piping
- Add HTML entity encoding/decoding
- Binary/ASCII conversion
