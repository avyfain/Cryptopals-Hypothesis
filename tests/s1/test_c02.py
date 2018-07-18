from itertools import repeat

from hypothesis import given, assume
from hypothesis.strategies import binary

from cryptopals.s1 import fixed_len_xor

def test_challenge2():
    # If your function works properly, then when you feed it the string:
    s1 = "1c0111001f010100061a024b53535009181c"

    # ... after hex decoding
    bs1 = bytes.fromhex(s1)

    # and when XOR'd against:
    bs2 = bytes.fromhex("686974207468652062756c6c277320657965")
    out = fixed_len_xor(bs1, bs2).hex()

    # ... should produce:
    assert out == "746865206b696420646f6e277420706c6179"


class TestXOR:
    """
    The properties tested below were taken from:
    https://web.archive.org/web/20051204172015/http://www.cs.umd.edu/class/sum2003/cmsc311/Notes/BitOp/xor.html
    Special thanks to Alex J. Champandard for pointing them out.
    """

    @given(binary(), binary(), binary())
    def test_associative(self, bs1, bs2, bs3):
        """
        A ⊕ ( B ⊕ C ) = ( A ⊕ B ) ⊕ C
        """
        assume(len(bs1) == len(bs2) == len(bs3))
        f = fixed_len_xor
        assert f(f(bs1, bs2), bs3) == f(bs1, f(bs2, bs3))

    @given(binary(), binary())
    def test_commutative(self, bs1, bs2):
        """
        A ⊕ B = B ⊕ A
        """
        assume(len(bs1) == len(bs2))
        assert fixed_len_xor(bs1, bs2) == fixed_len_xor(bs2, bs1)

    @given(binary())
    def test_identity(self, bs):
        """
        A ⊕ 0 = A
        """
        zeros = repeat(0)
        assert fixed_len_xor(bs, zeros) == bs

    @given(binary())
    def test_self_inverse(self, bs):
        """
        A ⊕ A = 0
        """
        assert all(v == 0 for v in fixed_len_xor(bs, bs))

    @given(binary())
    def test_negation(self, bs):
        """
        A ⊕ 1 = ~A
        """
        ones = repeat(1)
        negated = fixed_len_xor(bs, ones)
        assert bs == fixed_len_xor(negated, ones)
