"""
    Module to define the callback login usecase implementation
"""

# Tools
from src.tools.abstractions.abstract_usecase import AbstractUsecase

# Registries
from src.registries.login_registry import LoginRegistry

# Data models
from src.data_models.login_models import CallbackLogin
from src.data_models.oauth_models import State, GetProviderAccessTokenData, AccessTokenData, RecordTokenData

# Exceptions
from src.exceptions.invalid_parameter_exception import InvalidParameterException
from src.exceptions.registry_exception import RegistryException


class CallbackLoginUsecase(AbstractUsecase):
    """ Callback login usecase implementation """

    def __init__(self, login_registry: LoginRegistry):
        """ Login usecase constructor """

        self.login_registry: LoginRegistry = login_registry

    def execute(self, usecase_request: CallbackLogin) -> str:
        """ Method to perform callback login """

        state: str | None = usecase_request.state
        url: str | None = str(usecase_request.url) if usecase_request.url else None

        if not state or not url:
            raise InvalidParameterException("State and URL are mandatory for callback login usecae")

        oauth_provider: str = self.login_registry.get_oauth_provider(
            State(state=state)
        )
        if not oauth_provider:
            raise InvalidParameterException(f"No OAuth provider could be found in database for state : {state}")

        access_token_data: AccessTokenData = self.login_registry.get_oauth_provider_access_token(
            GetProviderAccessTokenData(
                oauth_provider=oauth_provider,
                state=state,
                authorization_response=url
            )
        )

        record_token_data = RecordTokenData(
            access_token=access_token_data.access_token,
            token_type=access_token_data.token_type,
            token_scope=access_token_data.token_scope,
            oauth_provider=oauth_provider
        )
        token_data_uuid: str | None = self.login_registry.record_token_data(record_token_data)
        if not token_data_uuid:
            raise RegistryException("No token data uuid has been returned by the insert query")

        return token_data_uuid
