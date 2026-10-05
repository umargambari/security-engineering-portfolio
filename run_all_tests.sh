#!/usr/bin/env bash
# Runs every project's test suite in its own throwaway virtualenv.
fail=0
for dir in fundamentals/*/ entry/*/; do
  [ -f "$dir/requirements.txt" ] || continue
  echo "=== $dir ==="
  (
    cd "$dir" || exit 1
    python3 -m venv .venv-test
    . .venv-test/bin/activate
    pip install -q -r requirements.txt
    python3 -m pytest tests -q
  ) || fail=1
  rm -rf "$dir/.venv-test"
done
exit $fail
