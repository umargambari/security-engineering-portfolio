# encoder

Multi-scheme encode/decode CLI with auto-detection. Supports Base64, hex,
URL encoding, and ROT13, plus a `detect` mode that guesses which scheme an
unknown string is likely encoded in.

## Why this exists

Decoding obfuscated strings — a suspicious query parameter, a payload
buried in a log line, an obfuscated C2 config value — is routine work when
triaging alerts. Doing it by hand across four different encodings gets
old fast; `detect` automates the "what am I even looking at" first step.

## Usage

```bash
python3 encoder.py encode --scheme base64 "hello world"
python3 encoder.py decode --scheme base64 "aGVsbG8gd29ybGQ="

# Not sure what encoding this is?
python3 encoder.py detect "aGVsbG8gd29ybGQ="
```

`--scheme` accepts `base64`, `hex`, `url`, `rot13`.

## Design notes

**Detection heuristics** (this is the interesting part):
- **URL**: presence of `%XX` escape sequences — high confidence, unambiguous.
- **Hex**: matches the hex character set, even length, then checks whether
  the decoded bytes are mostly printable ASCII (a random hex-looking string
  that decodes to binary noise is a weak match, not a strong one).
- **Base64**: matches the base64 charset/padding rules, then applies the
  same printable-ratio check on the decoded bytes.
- **ROT13**: the tricky one — ROT13 output is still just letters, so there's
  no structural signature. Instead, it decodes the candidate and compares
  how many common English letters (`e t a o i n s h r d l u`) appear before
  vs. after rotation. If rotating makes the text *more* English-like, it's
  flagged as a probable ROT13 candidate. This is a heuristic, not a
  guarantee — it's a starting hypothesis for a human to confirm, not a
  verdict.

Base64 decoding tolerates missing padding (`=`), since it's routinely
stripped in URLs and config values.

## Tests

```bash
python3 -m pytest tests/ -v
```

15 tests covering: round-trip encode/decode for all four schemes, unpadded
base64 decoding, each detection heuristic independently, ambiguous/short
input handling, unsupported-scheme errors, and CLI behavior.
