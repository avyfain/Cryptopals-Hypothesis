# This challenge works against a specific data set. Fuzzing makes no sense,
# therefore, we don't use hypothesis here.

from ..cryptopals.s1 import get_single_xor_key

def data_generator():
        with open('tests/data/s1c4data.txt', 'r') as f:
            for line in f:
                yield line.strip()

def test_challenge4():
    hex_lines = (bytes.fromhex(line) for line in data_generator())
    keyscorelines = (get_single_xor_key(bs) for bs in hex_lines)
    best = min(keyscorelines, key=lambda tup: tup[1])
    assert best[0] == '5'
