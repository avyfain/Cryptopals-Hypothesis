from string import ascii_uppercase

from hypothesis import given, example
from hypothesis.strategies import sampled_from, just

from cryptopals.s1 import break_single_key_xor, single_char_xor

def test_challenge3():
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    bs = bytes.fromhex(s)
    key, _ = break_single_key_xor(bs)
    assert key == 'X'

def snippets():
    with open('tests/data/english_sample.txt', 'rb') as f:
        text = f.read()
    sentences = [s.strip() for s in text.split(b'.') if len(s.split(b' ')) > 7]
    return sentences

@given(sampled_from(snippets()), sampled_from(ascii_uppercase), just(False))
@example(b"Cooking MC's like a pound of bacon", 'X', True)
def test_finding_key(bs, key, is_example):
    xord = single_char_xor(bs, key)
    retrieved_key, score = break_single_key_xor(xord)
    assert retrieved_key == key