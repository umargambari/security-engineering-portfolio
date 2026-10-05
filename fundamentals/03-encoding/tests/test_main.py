"""Tests for Encoding Toolkit."""
import pytest
from src.main import (
    encode_base64,
    decode_base64,
    encode_hex,
    decode_hex,
    encode_url,
    decode_url,
    encode_rot13,
    detect_encoding,
)


class TestBase64:
    def test_encode_base64(self):
        assert encode_base64("hello world") == "aGVsbG8gd29ybGQ="

    def test_decode_base64(self):
        assert decode_base64("aGVsbG8gd29ybGQ=") == "hello world"

    def test_decode_base64_invalid_input_raises(self):
        with pytest.raises(ValueError):
            decode_base64("not valid base64!!!")


class TestHex:
    def test_encode_hex(self):
        assert encode_hex("hello") == "68656c6c6f"

    def test_decode_hex(self):
        assert decode_hex("68656c6c6f") == "hello"

    def test_decode_hex_odd_length_raises(self):
        with pytest.raises(ValueError):
            decode_hex("abc")


class TestURL:
    def test_encode_url(self):
        assert encode_url("hello world") == "hello%20world"

    def test_decode_url(self):
        assert decode_url("hello%20world") == "hello world"

    def test_encode_url_special_characters(self):
        assert encode_url("a&b=c") == "a%26b%3Dc"


class TestROT13:
    def test_encode_rot13(self):
        assert encode_rot13("hello") == "uryyb"

    def test_rot13_applied_twice_returns_original(self):
        original = "hello world"
        assert encode_rot13(encode_rot13(original)) == original

    def test_rot13_non_alpha_unchanged(self):
        assert encode_rot13("hello, world! 123") == "uryyb, jbeyq! 123"


class TestDetectEncoding:
    def test_detect_base64(self):
        assert detect_encoding("aGVsbG8gd29ybGQ=") == "base64"

    def test_detect_hex(self):
        assert detect_encoding("68656c6c6f") == "hex"

    def test_detect_url(self):
        assert detect_encoding("hello%20world") == "url"
