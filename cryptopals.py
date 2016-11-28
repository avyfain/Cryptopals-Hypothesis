import base64


def hex_to_b64_bytes(given):
    return base64.b64encode(bytes.fromhex(given))


def fixed_xor(bs1, bs2):
    return bytes(a ^ b for a, b in zip(bs1, bs2))
