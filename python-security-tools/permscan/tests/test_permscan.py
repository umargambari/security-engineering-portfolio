import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from permscan import octal_perms, check_flags, scan, main, FLAG_BITS  # noqa: E402


def test_octal_perms_common_modes():
    assert octal_perms(0o100644) == "644"
    assert octal_perms(0o100777) == "777"
    assert octal_perms(0o104755) == "4755"  # setuid bit surfaces as a 4th digit, by design


def test_check_flags_detects_world_writable():
    mode = 0o100646  # rw-rw-rw- ish, world-writable
    reasons = check_flags(mode, {"world-writable"})
    assert "world-writable" in reasons


def test_check_flags_detects_setuid_and_setgid():
    mode = stat.S_ISUID | stat.S_ISGID | 0o755
    reasons = check_flags(mode, {"setuid", "setgid"})
    assert set(reasons) == {"setuid", "setgid"}


def test_check_flags_respects_disabled_checks():
    mode = stat.S_ISUID | 0o755
    reasons = check_flags(mode, {"setgid"})  # setuid check not enabled
    assert reasons == ()


def test_check_flags_clean_file_no_findings():
    mode = 0o100644
    reasons = check_flags(mode, set(FLAG_BITS))
    assert reasons == ()


def test_scan_finds_world_writable_file_recursive(tmp_path):
    nested = tmp_path / "sub"
    nested.mkdir()
    target = nested / "bad.sh"
    target.write_text("#!/bin/sh\n")
    os.chmod(target, 0o666)  # world-writable

    findings = list(scan(tmp_path, recursive=True))
    paths = [f.path for f in findings]
    assert str(target) in paths


def test_scan_finds_setuid_file(tmp_path):
    target = tmp_path / "suid_bin"
    target.write_text("binary-ish content")
    os.chmod(target, 0o4755)

    findings = list(scan(tmp_path, recursive=True))
    matched = [f for f in findings if f.path == str(target)]
    assert matched and "setuid" in matched[0].reasons


def test_scan_non_recursive_ignores_nested_files(tmp_path):
    nested = tmp_path / "sub"
    nested.mkdir()
    nested_file = nested / "bad.sh"
    nested_file.write_text("x")
    os.chmod(nested_file, 0o666)

    findings = list(scan(tmp_path, recursive=False))
    assert not any(f.path == str(nested_file) for f in findings)


def test_scan_clean_directory_returns_no_findings(tmp_path):
    (tmp_path / "clean.txt").write_text("hello")
    os.chmod(tmp_path / "clean.txt", 0o644)
    findings = list(scan(tmp_path, recursive=True))
    assert findings == []


def test_scan_respects_disabled_checks(tmp_path):
    target = tmp_path / "bad.sh"
    target.write_text("x")
    os.chmod(target, 0o666)

    findings = list(scan(tmp_path, recursive=True, enabled_checks={"setuid"}))
    assert findings == []  # world-writable check was disabled


def test_cli_scan_exits_one_when_findings(tmp_path, capsys):
    target = tmp_path / "bad.sh"
    target.write_text("x")
    os.chmod(target, 0o666)

    rc = main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "world-writable" in out


def test_cli_scan_exits_zero_when_clean(tmp_path, capsys):
    (tmp_path / "clean.txt").write_text("hi")
    os.chmod(tmp_path / "clean.txt", 0o644)

    rc = main(["scan", str(tmp_path)])
    assert rc == 0


def test_cli_json_output_is_valid_json(tmp_path, capsys):
    import json

    target = tmp_path / "bad.sh"
    target.write_text("x")
    os.chmod(target, 0o666)

    main(["scan", str(tmp_path), "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["permissions"] == "666"


def test_cli_invalid_directory_exits_two(tmp_path, capsys):
    missing = tmp_path / "nope"
    rc = main(["scan", str(missing)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not a directory" in err
