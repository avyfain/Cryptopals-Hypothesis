from hypothesis import given, example
from hypothesis.strategies import binary, integers

from cryptopals.s2 import pkcs7pad

fillchar = b'\x04'

@given(binary(min_size=1).filter(lambda x: x != fillchar),
       integers(min_value=5, max_value=100))
@example(b"YELLOW SUBMARINE", 20)
def test_challenge9_extra(s, blocksize):
    padded = pkcs7pad(s, blocksize)
    assert len(padded) % blocksize == 0
    assert padded.endswith(fillchar) or padded.endswith(s[-1:])
    assert not padded[len(s):] == fillchar * blocksize

def test_challenge9():
    s = b"YELLOW SUBMARINE"
    assert pkcs7pad(s, 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"
