"""
    Module to handle MFA key
"""

# Standard libraries
from base64 import b32encode

# Externals libraries
from Crypto.Random import get_random_bytes


def generate_new_mfa_key() -> str:
    """ Function to generate a new MFA key """

    random_bytes: bytes = get_random_bytes(10)  # 10 bytes to get a 16-long string in base32
    base32_encoded_random_bytes: bytes = b32encode(random_bytes)  # base32 is mandatory for some authenticators

    return base32_encoded_random_bytes.decode()
