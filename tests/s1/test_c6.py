import base64
from string import printable

from hypothesis import given, assume
from hypothesis.strategies import binary, text

from cryptopals.s1 import hamming_dist, break_repeat_key_xor, repeating_key_xor
from cryptopals.util import shortest_repeater, slow

def test_hamming_example():
    bs1 = b'this is a test'
    bs2 = b'wokka wokka!!!'
    assert hamming_dist(bs1, bs2) == 37

# The following properties were taken from:
# http://www.maths.manchester.ac.uk/~pas/code/notes/part2.pdf
@given(binary())
def test_hamming_same(bs):
    assert hamming_dist(bs, bs) == 0

@given(binary(min_size=1), binary(min_size=1))
def test_hamming_different(bs1, bs2):
    assume(len(bs1) == len(bs2))
    assume(bs1 != bs2)
    assert hamming_dist(bs1, bs2) > 0

@given(binary(), binary())
def test_hamming_commutative(bs1, bs2):
    assume(len(bs1) == len(bs2))
    assert hamming_dist(bs1, bs2) == hamming_dist(bs2, bs1)

@given(binary(), binary(), binary())
def test_hamming_trio(bs1, bs2, bs3):
    assume(len(bs1) == len(bs2) == len(bs3))
    d = hamming_dist
    assert d(bs1, bs3) <= d(bs1, bs2) + d(bs2, bs3)

def test_challenge6():
    with open('tests/data/s1c6data.txt', 'rb') as f:
        text = f.read()
    cipher = base64.b64decode(text)
    key = break_repeat_key_xor(cipher)
    deciphered = repeating_key_xor(cipher, key)
    assert deciphered.startswith(b"I'm back")

@slow
@given(text(min_size=3))
def test_large(key):
    assume(len(key.strip()) > 2)
    assume(set(key).issubset(printable))
    with open('tests/data/english_sample.txt', 'rb') as f:
        text = f.read()
    cipher = repeating_key_xor(text, key)
    retrieved_key = break_repeat_key_xor(cipher)
    assert shortest_repeater(key) == shortest_repeater(retrieved_key)
