# # This challenge works against a specific data set. Fuzzing makes no sense,
# # therefore, we don't use hypothesis here.

from cryptopals.s1 import detect_ecb


def test_challenge8():
    """
    S1C8 - AES in ECB mode
    https://cryptopals.com/sets/1/challenges/8

    In this file are a bunch of hex-encoded ciphertexts.
    One of them has been encrypted with ECB.
    Detect it.
    """
    def data_generator():
        with open('tests/data/s1c8.txt', 'r') as f:
            for line in f:
                yield line.strip()

    hex_lines = (bytes.fromhex(line) for line in data_generator())
    assert next(line for line in hex_lines if detect_ecb(line))
