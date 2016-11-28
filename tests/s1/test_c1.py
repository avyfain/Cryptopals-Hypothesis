import base64

from hypothesis import given, example
from hypothesis.strategies import binary

from cryptopals.s1 import hex_to_b64_bytes

@given(binary())
@example(b"49276d206b696c6c696e6720796f757220627261696e206c"
         b"696b65206120706f69736f6e6f7573206d757368726f6f6d")
def test_challenge1_extra(s):
    given = s.hex()
    expected = base64.b64encode(s)
    assert hex_to_b64_bytes(given) == expected
