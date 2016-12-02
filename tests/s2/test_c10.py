# This challenge works against a specific data set. Fuzzing makes no sense,
# therefore, we don't use hypothesis here.

import base64
from Crypto.Cipher import AES

from cryptopals.s1 import fixed_len_xor, chunks
from cryptopals.s2 import pkcs7pad, cbc_encrypt, cbc_decrypt

def test_simple():
    key = b"YELLOW SUBMARINE"
    plain = b"CBC mode is a block cipher mode that allows us to encrypt\
              irregularly-sized messages, despite the fact that a block\
              cipher natively only transforms individual blocks."

    encrypted = cbc_encrypt(plain, key)
    assert cbc_decrypt(encrypted, key) == plain


def test_challenge10():
    key = b"YELLOW SUBMARINE"
    with open('tests/data/s2c10.txt', 'rb') as f:
        text = base64.b64decode(f.read())

    decrypted = cbc_decrypt(text, key)
    assert decrypted.startswith(b"I'm back")
