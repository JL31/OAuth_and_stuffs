"""
    Module to define KMS interfaces
"""

# Standard libraries
from os import getenv

# External libraries
from boto3 import client


def get_encryption_key_data() -> tuple[bytes | None, bytes | None]:
    """ Function to fetch, into KMS, data that will be used to encrypt data """

    kms_client = client("kms", endpoint_url=getenv("AWS_ENDPOINT_URL"))
    if not kms_client:
        raise ValueError("Failed to create 'KMS' client")

    response: dict[str, str | bytes] = kms_client.generate_data_key(
        KeyId=getenv("ENCRYPTION_KEY_ARN"),
        KeySpec="AES_256"
    )

    return response.get("Plaintext"), response.get("CiphertextBlob")


def key_decryption_method(encrypted_data: bytes) -> bytes | None:
    """ Function to decrypt with KMS """

    kms_client = client("kms", endpoint_url=getenv("AWS_ENDPOINT_URL"))
    if not kms_client:
        raise ValueError("Failed to create 'KMS' client")

    response: dict[str, str | bytes] = kms_client.decrypt(CiphertextBlob=encrypted_data)

    return response.get("Plaintext")
