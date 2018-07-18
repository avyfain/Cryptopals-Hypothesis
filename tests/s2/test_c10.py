import base64

from hypothesis import given
from hypothesis.strategies import binary

from cryptopals.s2 import cbc_encrypt, cbc_decrypt

def test_challenge10():
    """
    S2C10 - Implement CBC mode
    https://cryptopals.com/sets/2/challenges/10
    """
    # The file here is intelligible (somewhat) when CBC decrypted
    with open('tests/data/s2c10.txt', 'rb') as f:
        text = base64.b64decode(f.read())

    # against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
    key = b"YELLOW SUBMARINE"
    decrypted = cbc_decrypt(text, key)
    assert decrypted.startswith(b"I'm back")


@given(binary(min_size=16, max_size=16), binary())
def test_cbc(key, plain):
    """
    Assert we can encrypt and decrypt and get back the correct plaintext.
    """
    encrypted = cbc_encrypt(plain, key)
    assert cbc_decrypt(encrypted, key) == plain
