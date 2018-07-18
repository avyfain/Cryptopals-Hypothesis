import base64

from hypothesis import given, example
from hypothesis.strategies import binary

from cryptopals.s1 import hex_to_b64_bytes

def test_challenge1():
    # The string:
    given = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    # Should produce:
    expected = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert hex_to_b64_bytes(given) == expected

class TestHexToB64:
    @given(binary())
    def test_encoding(self, b):
        given = b.hex()
        expected = base64.b64encode(b)
        assert hex_to_b64_bytes(given) == expected
