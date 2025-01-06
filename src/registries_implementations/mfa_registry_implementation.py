"""
    Module to define the OAuth registry implementation
"""

# Standard libraries
from io import BytesIO
from base64 import b64encode
from datetime import datetime, timezone
from logging import Logger

# Registries
from src.registries.mfa_registry import MFARegistry

# Queries
from src.registries_implementations.mfa_registry_queries import INSERT_MFA_KEY_QUERY

# Tools
from src.tools.logger.get_logger import get_logger

# Data models
from src.data_models.user_models import UserWithMFAData
from src.data_models.qr_code_models import BaseQRCode

# External libraries
from psycopg2 import extensions, Error
from qrcode import QRCode
from qrcode.constants import ERROR_CORRECT_L


# Global variables
ENCODING: str = "utf-8"


class MFARegistryImplementation(MFARegistry):
    """ MFA registry implementation """

    def __init__(self, database_connector: extensions.connection):
        """ Login registry implementation """

        self.logger: Logger = get_logger(self.__class__.__name__)

        self.database_connector: extensions.connection = database_connector

    def record_mfa_key(self, request: UserWithMFAData) -> None:
        """ Method to record a MFA key in database """

        insertion_datetime: datetime = datetime.now(timezone.utc)

        with self.database_connector.cursor() as database_cursor:
            try:
                database_cursor.execute(
                    query=INSERT_MFA_KEY_QUERY,
                    vars={
                        "created_at": insertion_datetime,
                        "updated_at": insertion_datetime,
                        "mfa_key": request.mfa_key,
                        "user_uuid": request.user_uuid
                    }
                )

                self.database_connector.commit()

            except Error as error:
                self.database_connector.rollback()
                self.logger.error(f"RECORD_MFA_KEY - psycopg2 error : {error.pgcode} - {error.pgerror}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected psycopg2 error : {error}")

            except Exception as error:
                self.database_connector.rollback()
                self.logger.error(f"RECORD_MFA_KEY - error : {error}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected error when interacting with PostgreSQL database : {error}")


    def create_mfa_key_qr_code(self, request: BaseQRCode) -> str:
        """ Method to create the QR Code associated to a MFA key """

        qr_code = QRCode(
            version=1,
            error_correction=ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr_code.add_data(request.qr_code)
        qr_code.make(fit=True)

        image = qr_code.make_image(fill_color="black", back_color="white")

        byte_stream = BytesIO()
        image.save(byte_stream)
        byte_stream.seek(0)

        return b64encode(byte_stream.getvalue()).decode(ENCODING)
