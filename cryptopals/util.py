# A file to keep all sorts of unrelated utilities
# Mostly used in tests.
import pytest

eng_freqs = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51,
             'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09,
             'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
             'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23,
             'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
             'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
             'Q': 0.10, 'Z': 0.07, ' ': 2}


def shortest_repeater(s):
    # Taken from Stack Overflow, by Buge
    # https://stackoverflow.com/questions/6021274/finding-shortest-repeating-cycle-in-word/33864413#33864413
    if not s:
        return s
    nxt = [0] * len(s)
    for i in range(1, len(nxt)):
        k = nxt[i - 1]
        while True:
            if s[i] == s[k]:
                nxt[i] = k + 1
                break
            elif k == 0:
                nxt[i] = 0
                break
            else:
                k = nxt[k - 1]
    small_piece_len = len(s) - nxt[-1]
    if len(s) % small_piece_len != 0:
        return s
    return s[0:small_piece_len]
