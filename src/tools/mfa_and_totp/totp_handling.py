"""
    Module to handle TOTP
"""

# Standard libraries
from base64 import b32decode
from time import time
from hmac import new


def calculate_totp(secret: str) -> str:
    """ Function to calculate TOTP using time and provided secret """

    decoded_key: bytes = b32decode(secret, casefold=True)
    now = int(time() // 30)
    now_in_bytes: bytes = now.to_bytes(length=8, byteorder="big")

    hashing_object = new(key=decoded_key, msg=now_in_bytes, digestmod="sha1")
    digest: bytes = hashing_object.digest()

    offset: int = digest[19] & 0xF
    code: bytes = digest[offset: offset + 4]

    code_as_int: int = int.from_bytes(code, byteorder="big") & 0x7FFFFFFF
    code_as_int = code_as_int % 1000000

    return "{:06d}".format(code_as_int)
