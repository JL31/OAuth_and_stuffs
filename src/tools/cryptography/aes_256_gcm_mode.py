"""
    Module to handle AES-256 with GCM mode encryption and decryption
"""

# External libraries
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def aes_gcm_encryption(encryption_key: bytes, data_to_encrypt: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Function to encrypt data using AES-256 algorithm with GCM mode

    Using the AES-256 algorithm implies that the key size must be 32 bytes (i.e. 256 bits).
    Indeed, the number associated to AES (AES-128, AES-192, AES-256) stands for the key size (in bits).
    See chapter "2.2 Key size and Rounds" in ref[1]

    It is also mandatory to randomly generate a 16-bytes (i.e. 128 bits) initial value and to provide it to the cipher.

    References :
    - [1] : https://www.ietf/org/rfc/rfc3686.txt
    """

    iv: bytes = get_random_bytes(16)

    cipher = AES.new(key=encryption_key, mode=AES.MODE_GCM, nonce=iv)

    encrypted_data: bytes
    tag: bytes
    encrypted_data, tag = cipher.encrypt_and_digest(data_to_encrypt)

    return iv, encrypted_data, tag


def aes_gcm_decryption(encryption_key: bytes, iv: bytes, data_to_decrypt: bytes, tag: bytes) -> bytes:
    """ Function to decrypt data using AES-256 algorithm with GCM mode """

    cipher = AES.new(key=encryption_key, mode=AES.MODE_GCM, nonce=iv)
    decrypted_data: bytes = cipher.decrypt_and_verify(data_to_decrypt, tag)

    return decrypted_data
