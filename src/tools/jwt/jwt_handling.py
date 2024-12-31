"""
    Module to create a JWT
"""

# Standard libraries
from datetime import datetime, timezone, timedelta
from os import getenv

# External libraries
from jwt import encode, decode

# Tools
from src.tools.aws_interfaces.secrets_manager_interface import get_secret


def encode_session_token(provided_data: dict, expires_delta: timedelta | None = None) -> str:
    """ Function to encode a session token to create a JWT from provided data """

    access_token_expiration_value: int | None = getenv("ACCESS_TOKEN_EXPIRATION_IN_MINUTES")
    if not access_token_expiration_value:
        raise ValueError("Impossible to get access token expiration environment variable value")
    token_expiration_period = float(access_token_expiration_value)

    expire: datetime = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=token_expiration_period))

    payload_to_encode: dict = provided_data.copy()
    payload_to_encode["exp"] = expire

    jwt_secrets: dict = get_secret("JWT")

    secret_key: str | None = jwt_secrets.get("secret_key")
    if not secret_key:
        raise ValueError("Impossible to fetch 'secret_key' from 'JWT' secret")

    algorithm: str | None = jwt_secrets.get("algorithm")
    if not algorithm:
        raise ValueError("Impossible to fetch 'algorithm' from 'JWT' secret")

    return encode(payload=payload_to_encode, key=secret_key, algorithm=algorithm)


def decode_session_token(session_token: str) -> str | None:
    """ Function to decode a session token from a JWT """

    jwt_secrets: dict = get_secret("JWT")

    secret_key: str | None = jwt_secrets.get("secret_key")
    if not secret_key:
        raise ValueError("Impossible to fetch 'secret_key' from 'JWT' secret")

    algorithm: str | None = jwt_secrets.get("algorithm")
    if not algorithm:
        raise ValueError("Impossible to fetch 'algorithm' from 'JWT' secret")

    decoded_payload: dict = decode(jwt=session_token, key=secret_key, algorithms=[algorithm])

    return decoded_payload.get("sub")
