from string import printable

from hypothesis import given, assume
from hypothesis.strategies import binary, text

from cryptopals.s1 import repeating_key_xor

def test_challenge5():
    bs1 = b"Burning 'em, if you ain't quick and nimble\n"\
          b"I go crazy when I hear a cymbal"

    out1 = repeating_key_xor(bs1, "ICE").hex()
    assert out1 == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623"\
                   "d63343c2a26226324272765272a282b2f20430a652e2c652a" \
                   "3124333a653e2b2027630c692b20283165286326302e27282f"

@given(binary(), text(min_size=1))
def test_inversion(bs, key):
    assume(all(c in printable for c in key))
    assert bs == repeating_key_xor(repeating_key_xor(bs, key), key)
