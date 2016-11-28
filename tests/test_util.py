from string import printable

from hypothesis import given, assume
from hypothesis.strategies import text, integers

from cryptopals.util import shortest_repeater

@given(text(), integers(min_value=1, max_value=10))
def test_reps(s, i):
    pat = s * i
    assert shortest_repeater(s) == shortest_repeater(pat)
