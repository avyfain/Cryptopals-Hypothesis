from string import ascii_uppercase

from hypothesis import given, example
from hypothesis.strategies import sampled_from, just

from ..cryptopals.s1 import get_single_xor_key, xor_against_single

def test_challenge3():
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    bs = bytes.fromhex(s)
    key, _ = get_single_xor_key(bs)
    assert key == 'X'

def snippets():
    with open('tests/english_sample.txt', 'rb') as f:
        text = f.read()
    sentences = [sentence.strip() for sentence in text.split(b'.')
                 if len(sentence.split(b' ')) > 7]
    return sentences

@given(sampled_from(snippets()), sampled_from(ascii_uppercase), just(False))
@example(b"Cooking MC's like a pound of bacon", 'X', True)
def test_finding_key(bs, key, is_example):
    xord = xor_against_single(bs, key)
    retrieved_key, score = get_single_xor_key(xord)
    assert score < 0.25

    if is_example:
        assert retrieved_key == key
