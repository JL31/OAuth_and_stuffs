"""
    Module to define an interface with the AWS Secrets Manager service
"""

# Standard libraries
from boto3 import client
from json import loads
from os import getenv
from botocore.exceptions import ClientError

# Exceptions
from src.exceptions.invalid_parameter_exception import InvalidParameterException


def get_secret(secret_name: str) -> dict[str, str]:
    """ Fetch an object from AWS Secrets Manager """

    secrets_manager_client = client("secretsmanager", endpoint_url=getenv("AWS_ENDPOINT_URL"))
    if not secrets_manager_client:
        raise ValueError("Failed to create 'SecretsManager' client")

    try:
        response: dict = secrets_manager_client.get_secret_value(SecretId=secret_name)

    except ClientError as error:
        raise ValueError(f"Failed to retrieve the secret '{secret_name}' : {error}")

    if "SecretString" in response:
        return loads(response.get("SecretString"))

    else:
        raise ValueError(f"The secret '{secret_name}' has no 'SecretString' value")


def get_specific_secret(secret_name: str, specific_secret_name: str) -> str | list[str] | None:
    """ Function to get a specific secret among secrets """

    fetched_secrets: dict[str, str] = get_secret(secret_name)
    if not fetched_secrets:
        raise InvalidParameterException(f"Impossible to fetch secrets for oauth provider : '{secret_name}'")

    return fetched_secrets.get(specific_secret_name)
