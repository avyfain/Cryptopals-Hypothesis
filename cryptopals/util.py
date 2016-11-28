# A file to keep all sorts of unrelated utilities
# Mostly used in tests.
import pytest

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

slow = pytest.mark.skipif(
    # pragma: no cover
    not pytest.config.getoption("--slow"),
    reason="need --runslow option to run")
