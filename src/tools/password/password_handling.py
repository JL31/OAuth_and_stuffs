"""
    Module to define tools to help handle passwords
"""

# Libs libraries
from hashlib import sha512


def hash_password(password: str) -> str:
    """ Function to hash a password """

    return sha512(password.encode("utf-8")).hexdigest()


def check_password(plain_password: str, hashed_password: str) -> bool:
    """ Function to check a password """

    return hash_password(plain_password) == hashed_password
