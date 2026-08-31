# permscan

Filesystem permission auditing CLI. Walks a directory tree and flags
files or directories with risky permission bits set — world-writable,
setuid, setgid — using `os.stat`/`os.walk` and bitwise checks against the
`stat` module's mode constants.

## Why this exists

Misconfigured file permissions are a recurring root cause in
privilege-escalation findings. This is a small, scriptable version of the
kind of check a config-auditing or posture-management tool runs, built to
be pipeline-friendly (JSON output, non-zero exit code on findings) rather
than just a one-off manual check.

## Usage

```bash
# Human-readable report
python3 permscan.py scan /var/www

# Top-level only, skip nested directories
python3 permscan.py scan /opt/app --no-recursive

# Machine-readable, for feeding into CI or another tool
python3 permscan.py scan /opt/app --json

# Narrow the checks
python3 permscan.py scan /opt/app --no-setuid --no-setgid
```

Exit codes: `0` clean, `1` findings present, `2` error (bad path).

## Design notes

- Uses `lstat` (not `stat`) so symlinks are evaluated by their own mode,
  not silently followed into whatever they point at.
- The octal permission string surfaces a 4th digit when setuid/setgid/sticky
  bits are set (e.g. `4755`) rather than dropping it — that leading digit
  is exactly the signal this tool exists to catch.
- Individual checks (`--no-world-writable`, `--no-setuid`, `--no-setgid`)
  can be disabled independently, so it's usable in environments where one
  of those is an accepted risk (e.g. a known setgid utility).

## Tests

```bash
python3 -m pytest tests/ -v
```

13 tests covering: octal formatting for ordinary and special-bit modes, flag
detection for each risky bit individually and combined, recursive vs
non-recursive traversal, clean directories, disabled-check behavior, JSON
output validity, and CLI exit codes.
