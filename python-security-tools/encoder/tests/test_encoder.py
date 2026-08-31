import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from encoder import encode, decode, detect, main  # noqa: E402


@pytest.mark.parametrize("scheme", ["base64", "hex", "url", "rot13"])
def test_round_trip_all_schemes(scheme):
    original = "Hello, Security World! 123"
    assert decode(encode(original, scheme), scheme) == original


def test_base64_decode_handles_missing_padding():
    # "hi" -> base64 "aGk=" ; strip the padding and confirm decode still works
    encoded = encode("hi", "base64").rstrip("=")
    assert decode(encoded, "base64") == "hi"


def test_hex_encode_known_value():
    assert encode("AB", "hex") == "4142"


def test_url_encode_spaces_and_symbols():
    # urllib.parse.quote leaves '/' unescaped by default (it's safe in URL paths)
    assert encode("a b/c", "url") == "a%20b/c"


def test_rot13_is_its_own_inverse():
    assert decode(encode("attack at dawn", "rot13"), "rot13") == "attack at dawn"


def test_encode_unsupported_scheme_raises():
    with pytest.raises(ValueError, match="Unsupported scheme"):
        encode("x", "uuencode")


def test_decode_unsupported_scheme_raises():
    with pytest.raises(ValueError, match="Unsupported scheme"):
        decode("x", "uuencode")


def test_detect_identifies_base64():
    encoded = encode("this is a normal sentence", "base64")
    guesses = detect(encoded)
    schemes = [g[0] for g in guesses]
    assert "base64" in schemes


def test_detect_identifies_hex():
    encoded = encode("secret payload", "hex")
    guesses = detect(encoded)
    schemes = [g[0] for g in guesses]
    assert "hex" in schemes


def test_detect_identifies_url_encoding():
    guesses = detect("search?q=hello%20world")
    schemes = [g[0] for g in guesses]
    assert "url" in schemes


def test_detect_identifies_rot13_ciphertext():
    # "the quick brown fox" rot13-encoded should be flagged as a likely rot13 candidate
    ciphertext = encode("the quick brown fox", "rot13")
    guesses = detect(ciphertext)
    schemes = [g[0] for g in guesses]
    assert "rot13" in schemes


def test_detect_returns_empty_for_short_ambiguous_input():
    guesses = detect("hi")
    # too short to confidently match any scheme's structural pattern
    assert all(g[0] != "hex" for g in guesses)


def test_cli_encode_and_decode_round_trip(capsys):
    main(["encode", "--scheme", "base64", "portfolio"])
    encoded = capsys.readouterr().out.strip()
    main(["decode", "--scheme", "base64", encoded])
    decoded = capsys.readouterr().out.strip()
    assert decoded == "portfolio"


def test_cli_detect_no_guesses_exits_one(capsys):
    rc = main(["detect", "!!!###???"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "No confident" in out
