# Hash Checker

A CLI tool that computes cryptographic hashes of files and verifies them against known-good values. The simplest form of file integrity validation — and one of the first things you'll do in any incident response or forensics workflow.

## Why this matters

Every time you download software, a security team verifies its hash. Every forensic image gets hashed before and after analysis. Every malware sample is identified by its hash. Understanding hashing isn't optional in security — it's day one.

## What you'll build

- Compute MD5 and SHA-256 hashes for any file
- Compare a file's hash against a known-good value and report match/mismatch
- Hash multiple files and output results in a clean table

## Skills you'll prove

- File I/O in Python (reading binary files)
- Using `hashlib` for cryptographic hashing
- CLI design with `argparse`
- String comparison and output formatting

## Getting started

```bash
make install
python src/main.py --help
```

## Commands

| Command | Description |
|---------|-------------|
| `hash` | Compute the hash of a file (default: SHA-256) |
| `verify` | Compare a file's hash against an expected value |

## Example usage

```bash
# Hash a file
python src/main.py hash firmware.bin

# Hash with MD5
python src/main.py hash firmware.bin --algorithm md5

# Verify a file against a known hash
python src/main.py verify firmware.bin abc123def456...
```

## Stretch goals

- Support additional algorithms (SHA-1, SHA-512, BLAKE2)
- Recursive directory hashing
- Output to CSV or JSON
- Read expected hashes from a checksum file (like `sha256sum` format)
