import base64
from collections import Counter
from itertools import repeat, cycle, zip_longest, combinations
from string import printable

eng_freqs = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51,
             'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09,
             'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
             'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23,
             'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
             'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
             'Q': 0.10, 'Z': 0.07, ' ': 2}

def hex_to_b64_bytes(given):
    return base64.b64encode(bytes.fromhex(given))

def hamming_dist(bs1, bs2):
    return sum(bin(v).count("1") for v in fixed_len_xor(bs1, bs2))

def fixed_len_xor(bs1, bs2):
    return bytes(a ^ b for a, b in zip(bs1, bs2))

def single_char_xor(bs, c):
    rep = repeat(ord(c))
    return fixed_len_xor(bs, rep)

def repeating_key_xor(bs, key):
    cyc = cycle((ord(c) for c in key))
    return fixed_len_xor(bs, cyc)

def break_single_key_xor(bs):
    scores = {}
    for c in printable:
        xord = single_char_xor(bs, c)
        if b' ' not in xord:
            continue
        scores[c] = english_score(xord, denominator=len(xord))

    inc = min(scores, key=scores.get)
    return inc, scores[inc]

def break_repeat_key_xor(bs, low=2, high=100):
    keysize = brute_force_keysize_search(bs, low, high)
    blocks = chunks(bs, keysize)
    trans = zip_longest(*blocks)
    clean_trans = ([v for v in block if v is not None] for block in trans)
    single_keys = (break_single_key_xor(block) for block in clean_trans)
    return ''.join(keyscore[0] for keyscore in single_keys)

def chunks(bs, keysize):
    return (bs[i:i + keysize] for i in range(0, len(bs), keysize))

def brute_force_keysize_search(bs, low, high, num_blocks=5):
    high = min(high, len(bs) // 2)
    keysizescores = []
    for keysize in range(low, high):
        genchuks = chunks(bs, keysize)
        blocks = (next(genchuks) for _ in range(num_blocks))
        block_perms = combinations(blocks, 2)
        distances = [hamming_dist(b1, b2) / keysize for b1, b2 in block_perms]
        avg_distance = sum(distances) / len(distances)
        keysizescores.append((keysize, avg_distance / keysize))
    return min(keysizescores, key=lambda ks: ks[1])[0]

def has_repeated_block(bs, blocksize=16):
    blocks = list(chunks(bs, blocksize))
    if len(blocks) > len(set(blocks)):
        return True
    else:
        return False

def english_score(fragment, denominator=None):
    denominator = denominator or len(fragment)
    counts = Counter(fragment.upper())
    freqs = {chr(k): 100 * v / denominator for k, v in counts.items()}
    diffs = {k: eng_freqs[k] - freqs.get(k, 0) for k in eng_freqs.keys()}
    return sum(diffs.values())
