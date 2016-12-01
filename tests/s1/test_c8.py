# # This challenge works against a specific data set. Fuzzing makes no sense,
# # therefore, we don't use hypothesis here.

from cryptopals.s1 import has_repeated_block

def data_generator():
    with open('tests/data/s1c8.txt', 'r') as f:
        for line in f:
            yield line.strip()

def test_challenge8():
    hex_lines = (bytes.fromhex(line) for line in data_generator())
    assert next(line for line in hex_lines if has_repeated_block(line))
