from string import printable

from hypothesis import given, assume
from hypothesis.strategies import binary, text

from cryptopals.s1 import repeating_key_xor

def test_challenge5():
    # Here is the opening stanza of an important work of the English language:
    bs = b"Burning 'em, if you ain't quick and nimble\n"\
         b"I go crazy when I hear a cymbal"

    # Encrypt it, under the key "ICE", using repeating-key XOR.
    out = repeating_key_xor(bs, "ICE").hex()

    # It should come out to:
    assert out == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623"\
                   "d63343c2a26226324272765272a282b2f20430a652e2c652a" \
                   "3124333a653e2b2027630c692b20283165286326302e27282f"

@given(binary(), text(min_size=1))
def test_inversion(bs, key):
    """
    Since we know XOR'ing is its own inverse, it should hold that:
    buffer == XOR(XOR(buffer, key), key)
    """
    assume(all(c in printable for c in key))
    assert bs == repeating_key_xor(repeating_key_xor(bs, key), key)
