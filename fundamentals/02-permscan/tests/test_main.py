"""Tests for Permission Scanner."""
import os
import stat
import tempfile
import pytest
from src.main import (
    get_permission_string,
    is_world_readable,
    is_world_writable,
    is_suid,
    is_sgid,
    scan_directory,
)


class TestPermissionString:
    def test_755_returns_rwxr_xr_x(self):
        assert get_permission_string(0o755) == "rwxr-xr-x"

    def test_644_returns_rw_r__r(self):
        assert get_permission_string(0o644) == "rw-r--r--"

    def test_777_returns_rwxrwxrwx(self):
        assert get_permission_string(0o777) == "rwxrwxrwx"


class TestPermissionChecks:
    def test_world_readable_644_true(self):
        assert is_world_readable(0o644) is True

    def test_world_readable_640_false(self):
        assert is_world_readable(0o640) is False

    def test_world_writable_666_true(self):
        assert is_world_writable(0o666) is True

    def test_world_writable_644_false(self):
        assert is_world_writable(0o644) is False

    def test_suid_4755_true(self):
        assert is_suid(0o4755) is True

    def test_suid_755_false(self):
        assert is_suid(0o755) is False


class TestScanDirectory:
    def test_world_writable_file_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "bad.txt")
            with open(filepath, "w") as f:
                f.write("test")
            os.chmod(filepath, 0o666)

            findings = scan_directory(tmpdir)

            assert len(findings) == 1
            assert "world-writable" in findings[0]["issues"]

    def test_filter_excludes_non_matching(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            readable_only = os.path.join(tmpdir, "readable.txt")
            with open(readable_only, "w") as f:
                f.write("test")
            os.chmod(readable_only, 0o644)

            writable = os.path.join(tmpdir, "writable.txt")
            with open(writable, "w") as f:
                f.write("test")
            os.chmod(writable, 0o666)

            findings = scan_directory(tmpdir, filter_type="world-writable")

            assert len(findings) == 1
            assert findings[0]["path"] == writable

    def test_empty_directory_no_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = scan_directory(tmpdir)
            assert findings == []
