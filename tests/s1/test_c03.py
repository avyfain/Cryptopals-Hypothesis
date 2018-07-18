from string import ascii_uppercase

from hypothesis import given, example
from hypothesis.strategies import sampled_from, just, binary

from cryptopals.s1 import break_single_char_xor, single_char_xor, english_score

def test_challenge3():
    # The hex encoded string:
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    bs = bytes.fromhex(s)

    # ... has been XOR'd against a single character. Find the key, decrypt the message.
    key, _ = break_single_char_xor(bs)
    assert key == 'X'

class TestEnglishScoring:
    @given(binary())
    def test_function_range(self, bs):
        """
        Any set of bytes should have some positive score.
        """
        assert english_score(bs) > 0

    def test_english_score_casing(self):
        """
        Englishness does not rely on case
        """
        english_lo = b'This is an english sentence'
        english_up = b'THIS IS AN ENGLISH SENTENCE'
        assert english_score(english_lo) == english_score(english_up)

    def test_english_score_comparison(self):
        """
        Englishness of englishness must be higher than that of gibberish.
        """
        english = b'This is an english sentence'
        not_english = b'vk\x1ar\xf6\xc0Z\xc5\x82\xb2\xca\xaa\xb9\x9a:\xd2'
        assert english_score(english) < english_score(not_english)


def snippets():
    with open('tests/data/english_sample.txt', 'rb') as f:
        text = f.read()
    sentences = [s.strip() for s in text.split(b'.') if len(s.split(b' ')) > 7]
    return sentences

@given(sampled_from(snippets()), sampled_from(ascii_uppercase))
def test_finding_key(bs, key):
    xord = single_char_xor(bs, key)
    retrieved_key, score = break_single_char_xor(xord)
    assert retrieved_key == key
