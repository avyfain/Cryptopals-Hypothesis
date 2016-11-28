from itertools import repeat

from hypothesis import given, assume
from hypothesis.strategies import binary

from ..cryptopals import fixed_xor

def test_challenge2():
    bs1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    bs2 = bytes.fromhex("686974207468652062756c6c277320657965")
    assert fixed_xor(bs1, bs2).hex() == "746865206b696420646f6e277420706c6179"

@given(binary(), binary(), binary())
def test_associative(bs1, bs2, bs3):
    # A ⊕ ( B ⊕ C ) = ( A ⊕ B ) ⊕ C
    assume(len(bs1) == len(bs2) == len(bs3))
    f = fixed_xor
    assert f(f(bs1, bs2), bs3) == f(bs1, f(bs2, bs3))

@given(binary(), binary())
def test_commutative(bs1, bs2):
    # A ⊕ B = B ⊕ A
    assume(len(bs1) == len(bs2))
    assert fixed_xor(bs1, bs2) == fixed_xor(bs2, bs1)

@given(binary())
def test_identity(bs):
    # A ⊕ 0 = A
    zeros = repeat(0)
    assert fixed_xor(bs, zeros) == bs

@given(binary())
def test_self_inverse(bs):
    # A ⊕ A = 0
    assert all(v == 0 for v in fixed_xor(bs, bs))

@given(binary())
def test_negation(bs):
    # A ⊕ 1 = ~A
    ones = repeat(1)
    negated = fixed_xor(bs, ones)
    assert bs == fixed_xor(negated, ones)
