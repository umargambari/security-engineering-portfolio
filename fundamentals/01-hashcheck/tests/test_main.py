"""Tests for Hash Checker."""
import tempfile
import os
import pytest
from src.main import hash_file, verify_hash


class TestHashFile:
    def test_sha256_known_content(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name

        try:
            result = hash_file(path, algorithm="sha256")
            expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            assert result == expected
        finally:
            os.remove(path)

    def test_md5_known_content(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name

        try:
            result = hash_file(path, algorithm="md5")
            expected = "5eb63bbbe01eeed093cb22bb8f5acdc3"
            assert result == expected
        finally:
            os.remove(path)

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            hash_file("this_file_does_not_exist.txt")


class TestVerifyHash:
    def setup_temp_file(self, content="hello world"):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            return f.name

    def test_matching_hash_returns_true(self):
        path = self.setup_temp_file()
        try:
            correct_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            assert verify_hash(path, correct_hash) is True
        finally:
            os.remove(path)

    def test_mismatched_hash_returns_false(self):
        path = self.setup_temp_file()
        try:
            wrong_hash = "0" * 65
            assert verify_hash(path, wrong_hash) is False
        finally:
            os.remove(path)

    def test_case_insensitive_match(self):
        path = self.setup_temp_file()
        try:
            correct_hash_upper = "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"
            assert verify_hash(path, correct_hash_upper) is True
        finally:
            os.remove(path)
