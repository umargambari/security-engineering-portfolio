import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hashcheck import compute_hash, verify_hash, main  # noqa: E402


@pytest.fixture
def sample_file(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"hello world")
    return f


@pytest.fixture
def large_file(tmp_path):
    f = tmp_path / "large.bin"
    f.write_bytes(b"A" * (CHUNK := 65536) * 3 + b"tail-bytes")
    return f


def test_compute_hash_known_sha256_value(sample_file):
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert compute_hash(sample_file, "sha256") == expected


def test_compute_hash_known_md5_value(sample_file):
    expected = hashlib.md5(b"hello world").hexdigest()
    assert compute_hash(sample_file, "md5") == expected


def test_compute_hash_chunked_matches_full_read(large_file):
    """Chunked reads must produce the same digest as hashing the whole file at once."""
    expected = hashlib.sha256(large_file.read_bytes()).hexdigest()
    assert compute_hash(large_file, "sha256", chunk_size=65536) == expected
    # Also verify with a tiny chunk size to stress the loop boundary
    assert compute_hash(large_file, "sha256", chunk_size=17) == expected


def test_compute_hash_unsupported_algorithm_raises(sample_file):
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        compute_hash(sample_file, "sha3_9000")


def test_verify_hash_match(sample_file):
    expected = hashlib.sha256(b"hello world").hexdigest()
    matched, actual = verify_hash(sample_file, expected, "sha256")
    assert matched is True
    assert actual == expected


def test_verify_hash_mismatch(sample_file):
    matched, actual = verify_hash(sample_file, "0" * 64, "sha256")
    assert matched is False
    assert actual == hashlib.sha256(b"hello world").hexdigest()


def test_verify_hash_case_and_whitespace_insensitive(sample_file):
    expected = hashlib.sha256(b"hello world").hexdigest()
    matched, _ = verify_hash(sample_file, f"  {expected.upper()}  ", "sha256")
    assert matched is True


def test_cli_compute_exits_zero_and_prints_digest(sample_file, capsys):
    rc = main(["compute", str(sample_file), "--algo", "sha256"])
    out = capsys.readouterr().out
    assert rc == 0
    assert hashlib.sha256(b"hello world").hexdigest() in out


def test_cli_verify_mismatch_exits_one(sample_file, capsys):
    rc = main(["verify", str(sample_file), "--hash", "0" * 64])
    out = capsys.readouterr().out
    assert rc == 1
    assert "MISMATCH" in out


def test_cli_missing_file_exits_two(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.bin"
    rc = main(["compute", str(missing)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not found" in err
