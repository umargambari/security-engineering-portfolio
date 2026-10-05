# Permission Scanner

A CLI tool that scans directories for files with overly permissive access rights. Flags world-readable, world-writable, and SUID/SGID files — the kinds of misconfigurations attackers look for first on a compromised Linux box.

## Why this matters

Misconfigured file permissions are one of the most common findings in penetration tests and security audits. A world-writable cron script, a readable SSH private key, or a rogue SUID binary can turn a low-privilege foothold into root access. Knowing how to find these is fundamental.

## What you'll build

- Walk a directory tree and read file permission metadata
- Flag files that are world-readable or world-writable
- Detect SUID/SGID bits on executables
- Display results in a clear, scannable table

## Skills you'll prove

- File system traversal with `os.walk` or `pathlib`
- Reading file metadata with `os.stat`
- Understanding Unix permission bits (octal notation)
- Filtering and formatting output

## Getting started

```bash
make install
python src/main.py --help
```

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan a directory for permission issues |

## Example usage

```bash
# Scan current directory
python src/main.py scan .

# Scan /etc and only show world-writable files
python src/main.py scan /etc --filter world-writable

# Scan with verbose output
python src/main.py scan /var --verbose
```

## Stretch goals

- Output to JSON for piping into other tools
- Check ownership (files owned by root but writable by others)
- Compare against a CIS benchmark permission checklist
- Add a `--fix` flag that suggests corrective `chmod` commands
