from Crypto.Cipher import AES

from cryptopals.s1 import fixed_len_xor, chunks

def pkcs7pad(bs, blocksize):
    l = len(bs)
    missing = l % blocksize
    numpad = blocksize - missing
    return bs + bytes([numpad])*numpad

def pkcs7unpad(bs):
    num_bytes = bs[-1]
    return bs[:-num_bytes]

def cbc_encrypt(bs, key, iv=None):
    blocksize = len(key)
    iv = iv or b'\x00' * blocksize
    cipher = AES.new(key, AES.MODE_ECB, iv)
    padded_bs = pkcs7pad(bs, blocksize)

    ciphertext = b''
    for plainblock in chunks(padded_bs, blocksize):
        cipherblock = cipher.encrypt(fixed_len_xor(plainblock, iv))
        ciphertext += cipherblock
        iv = cipherblock
    return ciphertext

def cbc_decrypt(bs, key, iv=None):
    blocksize = len(key)
    iv = iv or b'\x00' * blocksize
    cipher = AES.new(key, AES.MODE_ECB, iv)
    plaintext = b''

    for cipherblock in chunks(bs, blocksize):
        block = fixed_len_xor(cipher.decrypt(cipherblock), iv)
        plaintext += block
        iv = cipherblock
    return pkcs7unpad(plaintext)
