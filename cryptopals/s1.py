import base64
from collections import Counter
from itertools import repeat
from string import ascii_uppercase

eng_freqs = {'E': .01270, 'T': 0.0906, 'A': 0.0817, 'O': 0.0751,
             'I': 0.0697, 'N': 0.0675, 'S': 0.0633, 'H': 0.0609,
             'R': 0.0599, 'D': 0.0425, 'L': 0.0403, 'C': 0.0278,
             'U': 0.0276, 'M': 0.0241, 'W': 0.0236, 'F': 0.0223,
             'G': 0.0202, 'Y': 0.0197, 'P': 0.0193, 'B': 0.0129,
             'V': 0.0098, 'K': 0.0077, 'J': 0.0015, 'X': 0.0015,
             'Q': 0.0010, 'Z': 0.0007}

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
    denominator = float(len(bs))
    scores = {}

    for c in ascii_uppercase:
        counts = Counter(xor_against_single(bs, c).upper())
        freqs = {chr(k): v / denominator for k, v in counts.items()}
        scores[c] = english_score(freqs)

    inc = min(scores, key=scores.get)
    return inc, scores[inc]
