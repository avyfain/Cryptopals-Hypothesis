import os
import base64
from collections import Counter
from Crypto.Cipher import AES

from hypothesis import example, given
from hypothesis.strategies import binary

from cryptopals.s1 import detect_ecb
from cryptopals.s2 import encryption_oracle
from test_util import slow

@slow
@given(binary(min_size=8, max_size=64))
def test_challenge11(bs):
    """
    S1C11 - An ECB/CBC detection oracle
    https://cryptopals.com/sets/2/challenges/11

    Detect the block cipher mode the function is using each time.
    You should end up with a piece of code that, pointed at a block box that
    might be encrypting ECB or CBC, tells you which one is happening.
    """

    ciphertext, encryption_algo = encryption_oracle(bs)
    if detect_ecb(ciphertext):
        assert encryption_algo == 'ecb'
    # else:
    # we can't really assert the cbc encryption case