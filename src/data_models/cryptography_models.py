"""
    Module to define models used when handling cryptography topics
"""

# External libraries
from pydantic import BaseModel


# Simple models (based on BaseModel)
# ==================================

class CryptographicData(BaseModel):
    """ Model to define cryptographic data """

    encryption_key: bytes | None = None
    iv: bytes | None = None
    encrypted_data: bytes | None = None
    tag: bytes | None = None
