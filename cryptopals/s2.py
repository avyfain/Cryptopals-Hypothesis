def pkcs7pad(bs, blocksize, fillchar=b'\x04'):
    l = len(bs)
    missing = l % blocksize
    if missing:
        numpad = blocksize - missing
        return bs.ljust(l + numpad, fillchar)
    else:
        return bs
