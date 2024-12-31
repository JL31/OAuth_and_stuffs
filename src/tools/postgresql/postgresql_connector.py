"""
    Module to define a connector to a PostgreSQL database
"""

# Standard libraries
from logging import Logger
from os import getenv
from functools import reduce

# Tools
from src.tools.aws_interfaces.secrets_manager_interface import get_secret
from src.tools.logger.get_logger import get_logger

# External libraries
from boto3 import client
from psycopg2.extras import RealDictCursor
from psycopg2 import connect


# Configuration
logger: Logger = get_logger("PostgreSQL database connector")


def get_database_credentials(is_local_environment: bool = False) -> dict:
    """ Function to get a database credentials """

    if is_local_environment:
        database_secrets: dict = get_secret(secret_name="DatabaseGeneralCredentials")
        db_name: str = database_secrets.get("dbname")
        host: str = database_secrets.get("host")
        port: int = database_secrets.get("port")
        user: str = database_secrets.get("user")
        password: str = database_secrets.get("password")

    else:
        rds_client = client("rds", endpoint_url=getenv("AWS_ENDPOINT_URL"))
        host: str = getenv("RDS_ENDPOINT")
        db_name: str = getenv("RDS_DBNAME")
        port: str = getenv("RDS_PORT")
        user = "GeneralUser"
        password = rds_client.generate_db_auth_token(
            DBHostname=host,
            Port=int(port),
            DBUsername=user,
            Region=getenv("AWS_REGION")
        )

    return {
        "dbname": db_name,
        "host": host,
        "port": port,
        "user": user,
        "password": password
    }


def postgresql_connector(statement_timeout_value: int | None = None):
    """ Function to connect to a PostgreSQL database """

    is_local_environment: bool = getenv("APP_ENV") == "local"
    database_credentials: dict = get_database_credentials(is_local_environment)

    if statement_timeout_value and isinstance(statement_timeout_value, int):
        database_credentials = {
            **database_credentials,
            "options": f"'-c statement_timeout={statement_timeout_value}'"
        }

    dsn: str = " ".join(
        reduce(
            lambda accumulator, key: accumulator + [f"{key}={database_credentials[key]}"],
            database_credentials,
            []
        )
    )

    database_connector = connect(dsn=dsn, cursor_factory=RealDictCursor)

    return database_connector
