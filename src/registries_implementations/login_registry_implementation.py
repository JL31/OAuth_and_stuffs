"""
    Module to define the OAuth registry implementation
"""

# Standard libraries
from os import getenv
from logging import Logger
from datetime import datetime, timezone

# Registries
from src.registries.login_registry import LoginRegistry

# Queries
from src.registries_implementations.login_registry_queries import (
    INSERT_CRYPTO_DATA_QUERY,
    INSERT_TOKEN_DATA_QUERY,
    GET_OAUTH_TOKEN_QUERY,
    GET_USER_FROM_UUID_QUERY,
    INSERT_PASSWORD_DATA_QUERY,
    INSERT_USER_DATA_QUERY,
    GET_USER_FROM_CREDENTIALS_QUERY
)

# Tools
from src.tools.aws_interfaces.secrets_manager_interface import get_specific_secret
from src.tools.aws_interfaces.kms import get_encryption_key_data, key_decryption_method
from src.tools.cryptography.aes_256_gcm_mode import aes_gcm_encryption, aes_gcm_decryption
from src.tools.logger.get_logger import get_logger
from src.tools.password.password_handling import hash_password

# Data models
from src.data_models.oauth_models import (
    OAuthProvider,
    GetAuthorizationUrlData,
    RecordState,
    State,
    AccessTokenData,
    GetProviderAccessTokenData,
    AccessTokenDataToRecord,
    RecordTokenData,
    SessionToken,
    FetchedAccessTokenData
)
from src.data_models.cryptography_models import CryptographicData
from src.data_models.user_models import BaseUser, UserWithPassword
from src.data_models.login_models import LoginWithPassword

# External libraries
from requests_oauthlib import OAuth2Session
from redis import Redis
from psycopg2 import extensions, Error
from psycopg2.extras import RealDictRow

# Exceptions
from src.exceptions.invalid_parameter_exception import InvalidParameterException
from src.exceptions.registry_exception import RegistryException

# Global variables
ENCODING: str = "utf-8"


class LoginRegistryImplementation(LoginRegistry):
    """ Login registry implementation """

    def __init__(self, redis_client: Redis, database_connector: extensions.connection):
        """ Login registry implementation """

        self.logger: Logger = get_logger(self.__class__.__name__)

        self.redis_client: Redis = redis_client
        self.database_connector: extensions.connection = database_connector

    @staticmethod
    def _start_oauth_session(
        oauth_provider: str,
        state: str | None = None,
        scopes: list[str] = None,
        token: str | None = None
    ) -> OAuth2Session:
        """ Private static method to start an OAuth session """

        fetched_client_id: str = get_specific_secret(
            secret_name=oauth_provider,
            specific_secret_name="client_id"
        )
        if not fetched_client_id:
            raise InvalidParameterException(f"Impossible to fetch 'client id' from secrets for oauth provider : '{oauth_provider}'")

        session_parameters: dict = {
            "client_id": fetched_client_id,
            "redirect_uri": getenv("REDIRECT_OAUTH_URI")
        }

        if state:
            session_parameters["state"] = state

        if scopes:
            session_parameters["scope"] = " ".join(scopes)

        if token:
            session_parameters["token"] = token

        return OAuth2Session(**session_parameters)

    def get_authorization_url_data(self, request: OAuthProvider) -> GetAuthorizationUrlData:
        """ Method to get authorization URL data, such as authorization URL and state """

        fetched_authorization_base_url: str = get_specific_secret(
            secret_name=request.oauth_provider,
            specific_secret_name="authorization_base_url"
        )
        if not fetched_authorization_base_url:
            raise InvalidParameterException(f"Impossible to fetch 'authorization_base_url' from secrets for oauth provider : '{request.oauth_provider}'")

        fetched_scopes: list[str] = get_specific_secret(
            secret_name=request.oauth_provider,
            specific_secret_name="scopes"
        )

        oauth_session: OAuth2Session = self._start_oauth_session(
            oauth_provider=request.oauth_provider,
            scopes=fetched_scopes
        )

        authorization_url, state = oauth_session.authorization_url(fetched_authorization_base_url)

        return GetAuthorizationUrlData(authorization_url=authorization_url, state=state)

    def record_state(self, request: RecordState) -> None:
        """ Method to record OAuth state to prevent against CSRF attacks and to retrieve later OAuth provider"""

        try:
            self.redis_client.set(name=request.state, value=request.oauth_provider)

        except Exception as error:
            raise RegistryException(f"Impossible to record state : '{request.state}' and value : '{request.oauth_provider} into Redis database, got error : {error}")

    def get_oauth_provider(self, request: State) -> str:
        """ Method to get an OAuth provider from a provided state """

        try:
            oauth_provider_as_bytes: bytes | None = self.redis_client.get(name=request.state)

            if not oauth_provider_as_bytes:
                raise InvalidParameterException(f"No data fetched from database with state : {request.state}")

            return oauth_provider_as_bytes.decode(ENCODING)

        except Exception as error:
            raise RegistryException(f"Impossible to get OAuth provider from state '{request.state}' from Redis database, got error : {error}")

    def get_oauth_provider_access_token(self, request: GetProviderAccessTokenData) -> AccessTokenData:
        """ Method to get the access token of an OAuth provider """

        authorization_base_url: str = get_specific_secret(
            secret_name=request.oauth_provider,
            specific_secret_name="authorization_base_url"
        )
        if not authorization_base_url:
            raise InvalidParameterException(f"Impossible to fetch 'authorization_base_url' from secrets for oauth provider : '{request.oauth_provider}'")

        oauth_session: OAuth2Session = self._start_oauth_session(
            oauth_provider=request.oauth_provider,
            state=request.state
        )

        token_url: str = get_specific_secret(
            secret_name=request.oauth_provider,
            specific_secret_name="token_url"
        )
        if not token_url:
            raise InvalidParameterException(f"Impossible to fetch 'token_url' from secrets for oauth provider : '{request.oauth_provider}'")

        client_secret: str = get_specific_secret(
            secret_name=request.oauth_provider,
            specific_secret_name="client_secret"
        )
        if not client_secret:
            raise InvalidParameterException(f"Impossible to fetch 'client_secret' from secrets for oauth provider : '{request.oauth_provider}'")

        fetched_token_data: dict = oauth_session.fetch_token(
            token_url=token_url,
            client_secret=client_secret,
            authorization_response=request.authorization_response
        )
        if not fetched_token_data:
            raise RegistryException(f"Impossible to fetch token data for OAuth provider {request.oauth_provider}")

        return AccessTokenData(
            access_token=fetched_token_data.get("access_token"),
            token_type=fetched_token_data.get("token_type"),
            token_scope=fetched_token_data.get("scope")
        )

    @staticmethod
    def _sensitive_data_encryption(data_to_encrypt: str) -> CryptographicData:
        """ Private static method to encrypt sensitive data """

        encoded_data_to_encrypt: bytes = data_to_encrypt.encode(ENCODING)

        plain_text_encryption_key: bytes | None
        encrypted_encryption_key: bytes | None
        plain_text_encryption_key, encrypted_encryption_key = get_encryption_key_data()
        if not plain_text_encryption_key or not encrypted_encryption_key:
            raise ValueError("Impossible to fetch data from KMS to encrypt data")

        iv: bytes
        encrypted_token: bytes
        tag: bytes
        iv, encrypted_token, tag = aes_gcm_encryption(
            encryption_key=plain_text_encryption_key,
            data_to_encrypt=encoded_data_to_encrypt
        )

        return CryptographicData(
            encryption_key=encrypted_encryption_key,
            iv=iv,
            encrypted_data=encrypted_token,
            tag=tag,
        )

    def record_token_data(self, request: RecordTokenData) -> str | None:
        """ Method to record sensitive token data """

        encrypted_data: CryptographicData = self._sensitive_data_encryption(data_to_encrypt=request.access_token)
        data_to_record = AccessTokenDataToRecord(
            encryption_key=encrypted_data.encryption_key,
            iv=encrypted_data.iv,
            encrypted_data=encrypted_data.encrypted_data,
            tag=encrypted_data.tag,
            token_type=request.token_type,
            token_scope=request.token_scope
        )

        insertion_datetime: datetime = datetime.now(timezone.utc)

        with self.database_connector.cursor() as database_cursor:
            try:
                database_cursor.execute(
                    query=INSERT_CRYPTO_DATA_QUERY,
                    vars={
                        "created_at": insertion_datetime,
                        "updated_at": insertion_datetime,
                        "encryption_key": data_to_record.encryption_key,
                        "iv": data_to_record.iv,
                        "encrypted_token": data_to_record.encrypted_data,
                        "tag": data_to_record.tag,
                    }
                )
                token_cryptographic_data_result: RealDictRow = database_cursor.fetchone()

                token_cryptographic_data_uuid: str | None = token_cryptographic_data_result.get("uuid")
                if not token_cryptographic_data_uuid:
                    raise RegistryException("No token cryptographic data uuid returned by the insert query")

                database_cursor.execute(
                    query=INSERT_TOKEN_DATA_QUERY,
                    vars={
                        "created_at": insertion_datetime,
                        "updated_at": insertion_datetime,
                        "token_cryptographic_data": token_cryptographic_data_uuid,
                        "token_type": data_to_record.token_type,
                        "token_scope": data_to_record.token_scope,
                        "oauth_provider": request.oauth_provider,
                    }
                )
                token_data_result: RealDictRow = database_cursor.fetchone()

                self.database_connector.commit()

            except Error as error:
                self.database_connector.rollback()
                self.logger.error(f"RECORD_TOKEN_DATA - psycopg2 error : {error.pgcode} - {error.pgerror}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected psycopg2 error : {error}")

            except Exception as error:
                self.database_connector.rollback()
                self.logger.error(f"RECORD_TOKEN_DATA - error : {error}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected error when interacting with PostgreSQL database : {error}")

        return token_data_result.get("uuid") if token_data_result else None

    @staticmethod
    def _sensitive_data_decryption(crypto_data: CryptographicData) -> str:
        """ Private static method to decrypt sensitive data """

        decrypted_encryption_key: bytes | None = key_decryption_method(crypto_data.encryption_key)
        if not decrypted_encryption_key:
            raise ValueError("Impossible to decrypt encryption key using KMS")

        decrypted_data: bytes = aes_gcm_decryption(
            encryption_key=decrypted_encryption_key,
            iv=crypto_data.iv,
            data_to_decrypt=crypto_data.encrypted_data,
            tag=crypto_data.tag
        )

        return decrypted_data.decode(ENCODING)

    def get_oauth_token(self, request: SessionToken) -> FetchedAccessTokenData | None:
        """ Method to get OAuth token data """

        with self.database_connector.cursor() as database_cursor:
            try:
                database_cursor.execute(
                    query=GET_OAUTH_TOKEN_QUERY,
                    vars={
                        "token_data_uuid": request.session_token,
                    }
                )
                result: RealDictRow = database_cursor.fetchone()

                self.database_connector.commit()

            except Error as error:
                self.database_connector.rollback()
                self.logger.error(f"GET_TOKEN_DATA - psycopg2 error : {error.pgcode} - {error.pgerror}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected psycopg2 error : {error}")

            except Exception as error:
                self.database_connector.rollback()
                self.logger.error(f"GET_TOKEN_DATA - error : {error}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected error when interacting with PostgreSQL database : {error}")

            if result:
                decrypted_token: str = self._sensitive_data_decryption(
                    CryptographicData(
                        encryption_key=bytes(result.get("encryption_key")),  # cast to bytes is mandatory here since data are stored as bytes
                        iv=bytes(result.get("iv")),
                        encrypted_data=bytes(result.get("encrypted_token")),
                        tag=bytes(result.get("tag")),
                    )
                )

                return FetchedAccessTokenData(
                    access_token=decrypted_token,
                    token_type=result.get("token_type"),
                    token_scope=result.get("token_scope"),
                    oauth_provider=result.get("oauth_provider")
                )

        return None

    def get_user_from_uuid(self, request: BaseUser) -> BaseUser | None:
        """ Method to fetch a user from database from its uuid """

        with self.database_connector.cursor() as database_cursor:
            try:
                database_cursor.execute(
                    query=GET_USER_FROM_UUID_QUERY,
                    vars={
                        "user_uuid": request.uuid,
                    }
                )
                result: RealDictRow = database_cursor.fetchone()

                self.database_connector.commit()

            except Error as error:
                self.database_connector.rollback()
                self.logger.error(f"GET_USER_FROM_UUID - psycopg2 error : {error.pgcode} - {error.pgerror}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected psycopg2 error : {error}")

            except Exception as error:
                self.database_connector.rollback()
                self.logger.error(f"GET_USER_FROM_UUID - error : {error}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected error when interacting with PostgreSQL database : {error}")

            return BaseUser(uuid=result.get("uuid")) if result else None

    def add_user(self, request: UserWithPassword) -> BaseUser:
        """ Method to add a user into database """

        hashed_password: str = hash_password(request.password)

        insertion_datetime: datetime = datetime.now(timezone.utc)

        with self.database_connector.cursor() as database_cursor:
            try:
                database_cursor.execute(
                    query=INSERT_PASSWORD_DATA_QUERY,
                    vars={
                        "created_at": insertion_datetime,
                        "updated_at": insertion_datetime,
                        "hashed_password": hashed_password
                    }
                )
                user_password_data_result: RealDictRow = database_cursor.fetchone()

                user_password_uuid: str | None = user_password_data_result.get("uuid")
                if not user_password_uuid:
                    raise RegistryException("No password data uuid returned by the insert query")

                database_cursor.execute(
                    query=INSERT_USER_DATA_QUERY,
                    vars={
                        "created_at": insertion_datetime,
                        "updated_at": insertion_datetime,
                        "email": request.email,
                        "user_password_uuid": user_password_uuid,
                    }
                )
                user_data_result: RealDictRow = database_cursor.fetchone()

                self.database_connector.commit()

            except Error as error:
                self.database_connector.rollback()
                self.logger.error(f"ADD_USER - psycopg2 error : {error.pgcode} - {error.pgerror}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected psycopg2 error : {error}")

            except Exception as error:
                self.database_connector.rollback()
                self.logger.error(f"ADD_USER - error : {error}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected error when interacting with PostgreSQL database : {error}")

        return BaseUser(
            uuid=user_data_result.get("uuid"),
            email=user_data_result.get("email")
        ) if user_data_result else None

    def get_user_from_credentials(self, request: LoginWithPassword) -> BaseUser | None:
        """ Method to fetch a user from database from its credentials """

        hashed_password: str = hash_password(request.password)

        with self.database_connector.cursor() as database_cursor:
            try:
                database_cursor.execute(
                    query=GET_USER_FROM_CREDENTIALS_QUERY,
                    vars={
                        "email": request.email,
                        "hashed_password": hashed_password
                    }
                )
                result: RealDictRow = database_cursor.fetchone()

                self.database_connector.commit()

            except Error as error:
                self.database_connector.rollback()
                self.logger.error(f"GET_USER_FROM_CREDENTIALS - psycopg2 error : {error.pgcode} - {error.pgerror}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected psycopg2 error : {error}")

            except Exception as error:
                self.database_connector.rollback()
                self.logger.error(f"GET_USER_FROM_CREDENTIALS - error : {error}")
                self.logger.exception(error)
                raise ValueError(f"Unexpected error when interacting with PostgreSQL database : {error}")

            return BaseUser(uuid=result.get("uuid")) if result else None
