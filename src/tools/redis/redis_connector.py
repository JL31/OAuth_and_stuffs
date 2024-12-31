"""
    Module to define a connector to a Redis database
"""

# External libraries
from redis import Redis

# Tools
from src.tools.aws_interfaces.secrets_manager_interface import get_secret


def get_database_credentials() -> dict:
    """ Function to get a database credentials """

    database_secrets: dict = get_secret(secret_name="RedisDatabaseCredentials")

    return {
        "host": database_secrets.get("host"),
        "port": database_secrets.get("port"),
        "database": database_secrets.get("database")
    }


def redis_connector() -> Redis:
    """ Function that returns a connector to a Redis database """

    database_credentials: dict = get_database_credentials()

    return Redis(
        host=database_credentials.get("host"),
        port=database_credentials.get("port"),
        db=database_credentials.get("database")
    )
