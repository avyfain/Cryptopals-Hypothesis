"""
Crypto Challenge Set 1
https://cryptopals.com/sets/1

This is the qualifying set.
We picked the exercises in it to ramp developers up gradually into coding cryptography,
but also to verify that we were working with people who were ready to write code.

This set is relatively easy. With one exception,
most of these exercises should take only a couple minutes.
But don't beat yourself up if it takes longer than that.
It took Alex two weeks to get through the set!

If you've written any crypto code in the past,
you're going to feel like skipping a lot of this. Don't skip them.
At least two of them (we won't say which) are important stepping stones to later attacks.
"""

import base64
from collections import Counter
from itertools import repeat, cycle, zip_longest, combinations
from string import printable
from statistics import mean
from operator import itemgetter

from cryptopals.util import eng_freqs

from typing import Iterator, List, Tuple, Union, Sequence, Iterable
from typing import TypeVar, Optional, Iterator

T = TypeVar('T')

def hex_to_b64_bytes(given: str) -> bytes:
    """
    S1C1 - Convert hex to base64
    https://cryptopals.com/sets/1/challenges/1
    """
    return base64.b64encode(bytes.fromhex(given))

def fixed_len_xor(bs1: bytes, bs2: bytes) -> bytes:
    """
    S1C2 - Fixed XOR
    https://cryptopals.com/sets/1/challenges/2

    Write a function that takes two equal-length buffers and produces their XOR combination.
    """
    return bytes(a ^ b for a, b in zip(bs1, bs2))

def single_char_xor(bs: bytes, c: str) -> bytes:
    """
    S1C3 - Single-byte XOR cipher
    https://cryptopals.com/sets/1/challenges/3
    """
    rep = repeat(ord(c))
    return fixed_len_xor(bs, rep)

def english_score(fragment: bytes, denominator: Optional[int] = None) -> float:
    """
    S1C3 - Score plaintext's "english-ness"
    https://cryptopals.com/sets/1/challenges/3

    Devise some method for "scoring" a piece of English plaintext.
    Character frequency is a good metric.
    """
    denominator = denominator or len(fragment)
    counts = Counter(fragment.upper())
    freqs = {chr(k): 100 * v / denominator
             for k, v in counts.items()}
    diffs = {k: eng_freqs[k] - freqs.get(k, 0)
             for k in eng_freqs}
    return sum(diffs.values())

def break_single_char_xor(bs: bytes) -> Tuple[str, float]:
    """
    S1C3 - Break single-byte XOR cipher
    https://cryptopals.com/sets/1/challenges/3

    Evaluate each output [of the english scoring function]
    and choose the one with the best score.
    """
    inc, inc_score = '', 100.0

    for c in printable:
        xord = single_char_xor(bs, c)
        candidate_score = english_score(xord)
        if candidate_score < inc_score:
            inc, inc_score = c, candidate_score
    return inc, inc_score

def repeating_key_xor(bs: bytes, key: str) -> bytes:
    """
    S1C5 - Implement repeating-key XOR
    https://cryptopals.com/sets/1/challenges/5

    In repeating-key XOR, you'll sequentially apply each byte of the key
    """
    cyc = cycle((ord(c) for c in key))
    return fixed_len_xor(bs, cyc)

def hamming_dist(bs1: bytes, bs2: bytes) -> int:
    """
    S1C6 - Break repeating-key XOR
    https://cryptopals.com/sets/1/challenges/6

    Write a function to compute the edit distance/Hamming distance between two strings.
    The Hamming distance is just the number of differing bits.

    This can be solved by XORing both strings, and adding up the bits.
    """
    return sum(bin(v).count("1") for v in fixed_len_xor(bs1, bs2))

def break_repeating_key_xor(bs: bytes, low: int = 2, high: int = 100) -> str:
    """
    S1C6 - Break repeating-key XOR
    https://cryptopals.com/sets/1/challenges/6
    """

    # Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    keysize = brute_force_keysize_search(bs, low, high)

    # Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    blocks = chunks(bs, keysize)

    # Now transpose the blocks:
    # make a block that is the first byte of every block,
    # and a block that is the second byte of every block, and so on.
    trans = zip_longest(*blocks)
    clean_trans: Iterator[List[bytes]]
    clean_trans= ([char for char in block if char is not None] for block in trans)

    # Solve each block as if it was single-character XOR.
    # For each block, the single-byte XOR key that produces the best looking
    # histogram is the repeating-key XOR key byte for that block.
    single_keys = (break_single_char_xor(block) for block in clean_trans)

    # Put them together and you have the key.
    return ''.join(keyscore[0] for keyscore in single_keys)

def chunks(c: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    yield from (c[i:i + size] for i in range(0, len(c), size))


def brute_force_keysize_search(bs: bytes, low: int, high: int, num_blocks: int = 5) -> int:
    """
    S1C6 - Break repeating-key XOR
    https://cryptopals.com/sets/1/challenges/6

    For each KEYSIZE, take the first KEYSIZE worth of bytes,
    and the second KEYSIZE worth of bytes, and find the edit distance between them.
    Normalize this result by dividing by KEYSIZE.

    The KEYSIZE with the smallest normalized edit distance is probably the key.
    You could proceed perhaps with the smallest 2-3 KEYSIZE values.
    Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    """

    # We know that keysize must be capped to have at least two comparable blocks.
    high = min(high, len(bs) // 2)
    key_size_scores = []

    for keysize in range(low, high):
        genchunks = chunks(bs, keysize)
        blocks = (next(genchunks) for _ in range(num_blocks))
        block_pairs = combinations(blocks, 2)
        norm_distances = [hamming_dist(b1, b2) / keysize for b1, b2 in block_pairs]
        avg_norm_distance = mean(norm_distances)
        key_size_scores.append((keysize, avg_norm_distance / keysize))
    return min(key_size_scores, key=itemgetter(1))[0]

def detect_ecb(bs: bytes, blocksize: int = 16) -> bool:
    """
    S1C6 - Detect AES in ECB mode
    https://cryptopals.com/sets/1/challenges/6

    ...the problem with ECB is that it is stateless and deterministic;
    the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

    This means we can detect if ecb is applied by checking whether we see the same
    block more than once in the input.
    """
    blocks = list(chunks(bs, blocksize))
    return len(blocks) > len(set(blocks))
