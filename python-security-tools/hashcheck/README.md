# hashcheck

File integrity verification CLI. Computes and verifies cryptographic hashes
using fixed-size chunked reads, so it stays memory-safe on files far larger
than available RAM — the kind of thing that matters when triaging a
multi-GB disk image or log bundle during an incident.

## Why this exists

Hash verification is a basic building block of incident response and
forensics: confirming a downloaded artifact hasn't been tampered with,
checking a file against a known-malicious hash, or proving chain-of-custody
on evidence. This is a from-scratch implementation of that primitive.

## Usage

```bash
# Compute a hash
python3 hashcheck.py compute suspicious_file.exe --algo sha256

# Verify against an expected hash (e.g. from a vendor advisory or VirusTotal)
python3 hashcheck.py verify suspicious_file.exe --hash 9f86d0... --algo sha256
```

Supports `md5`, `sha1`, `sha256` (default), `sha512`.

Exit codes: `0` match, `1` mismatch, `2` error (bad input/missing file).

## Design notes

- Reads in 64KB chunks (`hashlib` update loop) instead of loading the whole
  file into memory — deliberate, not incidental, given how large forensic
  artifacts get.
- Verification compares case- and whitespace-insensitively, since hashes get
  pasted around in mixed case from different tools.

## Tests

```bash
python3 -m pytest tests/ -v
```

10 tests covering: known-value hashing across algorithms, chunked-vs-full-read
equivalence (including a small chunk size to stress the loop boundary),
mismatch detection, unsupported-algorithm handling, and CLI exit codes.
