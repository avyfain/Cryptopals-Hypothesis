import os
import base64
from string import printable

from hypothesis import given, assume
from hypothesis.strategies import binary, one_of

from cryptopals.s1 import detect_ecb
from cryptopals.s2 import ecb_encrypt, Oracle, guess_blocksize, guess_unknown_string_size, break_ecb
from cryptopals.util import shortest_repeater
from test_util import slow

def test_challenge12():
    """
    S1C12 - Byte-at-a-time ECB decryption (Simple)
    https://cryptopals.com/sets/2/challenges/12
    """

    unknown_blocksize = 16
    key = b'\xae\xb7\xe2\x96\xa2\xf9s<,Xr\xdb\x90&\xaa\xf0'
    with open('tests/data/s2c12.txt', 'rb') as f:
        unknown = base64.b64decode(f.read())

    oracle = Oracle(key, unknown)

    blocksize = guess_blocksize(oracle)
    assert blocksize == unknown_blocksize
    assert detect_ecb(oracle(b'YELLOW SUBMARINE'*2))

    retrieved_string = break_ecb(oracle)
    assert retrieved_string.startswith(b'Rollin')
    assert retrieved_string.endswith(b'drove by')

@given(binary(min_size=8, max_size=64),
       one_of(binary(min_size=16, max_size=16),
              binary(min_size=32, max_size=32)))
def test_guess_blocksize(unknown_text, key):
    """
    Generate some random text and a random key of size 16 or 32
    build an oracle with them, and guess its block size
    """
    oracle = Oracle(key, unknown_text)
    guess = guess_blocksize(oracle)

    assert guess == len(key)

@given(binary(min_size=8, max_size=64),
       one_of(binary(min_size=16, max_size=16),
              binary(min_size=32, max_size=32)))
def test_guess_unknown_string_size(unknown_text, key):
    """
    Generate some random text and a random key of size 16 or 32
    build an oracle with them, and guess the length of the unknown text
    """
    oracle = Oracle(key, unknown_text)
    guess = guess_unknown_string_size(oracle)

    assert guess == len(unknown_text)