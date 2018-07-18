from hypothesis import given, example, note
from hypothesis.strategies import binary, integers

from cryptopals.s2 import pkcs7pad, pkcs7unpad

def test_challenge9():
    """
    S2C9 - Implement PKCS#7 padding
    https://cryptopals.com/sets/2/challenges/9
    """
    plaintext = b"YELLOW SUBMARINE"
    # ... padded to 20 bytes would be:
    padded = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    assert pkcs7pad(plaintext, 20) == padded


class TestPadding:
    @given(binary(min_size=1), integers(min_value=5, max_value=100))
    @example(b"YELLOW SUBMARINE", 20)
    def test_padding_to_blocksize(self, s, blocksize):
        padded = pkcs7pad(s, blocksize)
        assert len(padded) % blocksize == 0

        padsize = len(padded[len(s):])
        assert padded.endswith(padsize * bytes([padsize]))

    @given(binary(min_size=1), integers(min_value=5, max_value=100))
    @example(b"YELLOW SUBMARINE", 20)
    def test_inverse(self, s, blocksize):
        padded = pkcs7pad(s, blocksize)
        assert pkcs7unpad(padded) == s
