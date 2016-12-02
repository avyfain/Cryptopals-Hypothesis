from hypothesis import given, example, note
from hypothesis.strategies import binary, integers

from cryptopals.s2 import pkcs7pad, pkcs7unpad


@given(binary(min_size=1), integers(min_value=5, max_value=100))
@example(b"YELLOW SUBMARINE", 20)
def test_pkcs7pad(s, blocksize):
    padded = pkcs7pad(s, blocksize)
    assert len(padded) % blocksize == 0

    padsize = len(padded[len(s):])
    assert padded.endswith(padsize * bytes([padsize]))

@given(binary(min_size=1), integers(min_value=5, max_value=100))
@example(b"YELLOW SUBMARINE", 20)
def test_pkcs7unpad(s, blocksize):
    padded = pkcs7pad(s, blocksize)
    assert pkcs7unpad(padded) == s


def test_challenge9():
    s = b"YELLOW SUBMARINE"
    assert pkcs7pad(s, 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"
