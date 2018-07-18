import base64
from string import printable

from hypothesis import given, assume, note
from hypothesis.strategies import binary, text

from cryptopals.s1 import hamming_dist, break_repeating_key_xor, repeating_key_xor, english_score
from cryptopals.util import shortest_repeater
from test_util import slow

def test_challenge6():
    """
    S1C6 - Break repeating-key XOR
    https://cryptopals.com/sets/1/challenges/6

    There's a file here.
    It's been base64'd after being encrypted with repeating-key XOR.
    Decrypt it.
    """
    with open('tests/data/s1c6.txt', 'rb') as f:
        text = f.read()
    cipher = base64.b64decode(text)
    key = break_repeating_key_xor(cipher)
    deciphered = repeating_key_xor(cipher, key)
    assert deciphered.startswith(b"I'm back")

class TestHammingDistance:
    # The following properties were taken from:
    # http://www.maths.manchester.ac.uk/~pas/code/notes/part2.pdf
    @given(binary())
    def test_hamming_same(self, bs):
        """
        The distance between a string and itself is 0
        """
        assert hamming_dist(bs, bs) == 0

    @given(binary(min_size=1), binary(min_size=1))
    def test_hamming_different(self, bs1, bs2):
        """
        The distance between two different strings must be positive
        """
        assume(len(bs1) == len(bs2))
        assume(bs1 != bs2)
        assert hamming_dist(bs1, bs2) > 0

    @given(binary(), binary())
    def test_hamming_commutative(self, bs1, bs2):
        """
        The order of inputs should not matter.
        """
        assume(len(bs1) == len(bs2))
        assert hamming_dist(bs1, bs2) == hamming_dist(bs2, bs1)

    @given(binary(), binary(), binary())
    def test_hamming_trio(self, bs1, bs2, bs3):
        """
        The distance between any two points X and Z must be less or equal
        to the distance from X to any point Y plus the distance from Y to Z.
        ie,  d(x, z) ≤ d(x, y) + d(y, z)

        If the distance is equal, then point Z must be on the same line as X and Y.
        """
        assume(len(bs1) == len(bs2) == len(bs3))
        d = hamming_dist
        assert d(bs1, bs3) <= d(bs1, bs2) + d(bs2, bs3)

def test_hamming_example():
    """
    S1C6 - Break repeating-key XOR
    https://cryptopals.com/sets/1/challenges/6
    """
    bs1 = b'this is a test'
    bs2 = b'wokka wokka!!!'
    assert hamming_dist(bs1, bs2) == 37

@slow
@given(text(min_size=3, max_size=40))
def test_large(key):
    """
    Encrypt and retrieve the key for large amounts of english text,
    with a variety of key sizes.

    Notice that if the key is "akey" we can also solve it with the "akeyakey"
    so we must ensure that any key we're testing is not repeated within itself,
    in order to assert that the property is held
    """
    assume(len(key.strip()) > 2)
    assume(set(key).issubset(printable))
    assume(shortest_repeater(key) == key)
    with open('tests/data/english_sample.txt', 'rb') as f:
        text = f.read(200)
    ciphertext = repeating_key_xor(text, key)
    retrieved_key = break_repeating_key_xor(ciphertext)
    note("retrieved_key: " + retrieved_key)
    assert key == shortest_repeater(retrieved_key)
