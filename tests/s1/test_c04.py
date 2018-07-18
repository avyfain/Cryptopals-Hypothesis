# This challenge works against a specific data set. Fuzzing makes no sense,
# therefore, we don't use hypothesis here.

from cryptopals.s1 import break_single_char_xor
from operator import itemgetter

def test_challenge4():
    """
    S1C4 - Detect single-character XOR
    https://cryptopals.com/sets/1/challenges/3

    One of the 60-character strings in this file has been encrypted by single-character XOR. Find it.
    """
    def data_generator():
        with open('tests/data/s1c4.txt', 'r') as f:
            for line in f:
                yield line.strip()

    hex_lines = (bytes.fromhex(line) for line in data_generator())
    keyscorelines = (break_single_char_xor(bs) for bs in hex_lines)
    key, score = min(keyscorelines, key=itemgetter(1))
    assert key == '5'


