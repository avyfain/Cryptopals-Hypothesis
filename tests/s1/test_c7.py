# This challenge works against a specific data set. Fuzzing makes no sense,
# therefore, we don't use hypothesis here.

import base64
from Crypto.Cipher import AES

def test_challenge7():
    key = b"YELLOW SUBMARINE"
    with open('tests/data/s1c7.txt', 'rb') as f:
        text = f.read()

    ciphertext = base64.b64decode(text)
    cipher = AES.new(key, AES.MODE_ECB)
    deciphered = cipher.decrypt(ciphertext)
    assert deciphered.startswith(b"I'm back")
