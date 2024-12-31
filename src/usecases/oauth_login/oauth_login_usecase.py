"""
    Module to define the OAuth login usecase
"""

# Tools
from src.tools.abstractions.abstract_usecase import AbstractUsecase

# Registries
from src.registries.login_registry import LoginRegistry

# Data models
from src.data_models.oauth_models import OAuthProvider, GetAuthorizationUrlData, RecordState, AuthorizationUrl

# Exceptions
from src.exceptions.invalid_parameter_exception import InvalidParameterException


class OAuthLoginUsecase(AbstractUsecase):
    """ OAuth login usecase implementation """

    def __init__(self, login_registry: LoginRegistry):
        """ OAuth login usecase constructor """

        self.login_registry: LoginRegistry = login_registry

    def execute(self, usecase_request: OAuthProvider) -> AuthorizationUrl:
        """ Method to perform OAuth login """

        oauth_provider: str = usecase_request.oauth_provider

        fetched_data: GetAuthorizationUrlData = self.login_registry.get_authorization_url_data(
            OAuthProvider(oauth_provider=oauth_provider)
        )
        if not fetched_data.authorization_url:
            raise InvalidParameterException(f"Impossible to fetch 'authorization_url' from OAuth provider '{oauth_provider}'")

        if not fetched_data.state:
            raise InvalidParameterException(f"Impossible to fetch 'state' from OAuth provider '{oauth_provider}'")

        self.login_registry.record_state(
            RecordState(
                state=fetched_data.state,
                oauth_provider=oauth_provider
            )
        )

        return AuthorizationUrl(authorization_url=fetched_data.authorization_url)
