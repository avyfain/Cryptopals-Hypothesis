import base64
from collections import Counter
from itertools import repeat
from string import printable

eng_freqs = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51,
             'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09,
             'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
             'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23,
             'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
             'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
             'Q': 0.10, 'Z': 0.07, ' ': 5}

def hex_to_b64_bytes(given):
    return base64.b64encode(bytes.fromhex(given))

def fixed_xor(bs1, bs2):
    return bytes(a ^ b for a, b in zip(bs1, bs2))

def english_score(freqs):
    diffs = {k: eng_freqs[k] - freqs.get(k, 0) for k in eng_freqs.keys()}
    return sum(diffs.values())

def xor_against_single(bs, c):
    rep = repeat(ord(c))
    return fixed_xor(bs, rep)

def get_single_xor_key(bs):
    denominator = len(bs)
    scores = {}

    for c in printable:
        xord = xor_against_single(bs, c).upper()
        counts = Counter(xord)
        if b' ' not in xord:
            continue
        freqs = {chr(k): 100.0 * v / denominator for k, v in counts.items()}
        scores[c] = english_score(freqs)

    inc = min(scores, key=scores.get)
    return inc, scores[inc]
