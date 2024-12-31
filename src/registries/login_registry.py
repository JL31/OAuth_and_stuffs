"""
    Module to define the abstract Login registry
"""

# Standard libraries
from abc import ABC, abstractmethod

# Data models
from src.data_models.oauth_models import OAuthProvider, GetAuthorizationUrlData, RecordState, State, AccessTokenData, GetProviderAccessTokenData, RecordTokenData
from src.data_models.user_models import BaseUser, UserWithPassword
from src.data_models.login_models import LoginWithPassword


class LoginRegistry(ABC):
    """ Login abstract registry definition """

    @abstractmethod
    def get_authorization_url_data(self, request: OAuthProvider) -> GetAuthorizationUrlData:
        """ Method to get authorization URL data, such as authorization URL and state """

    @abstractmethod
    def record_state(self, request: RecordState) -> None:
        """ Method to record OAuth state to prevent against CSRF attacks and to retrieve later OAuth provider"""

    @abstractmethod
    def get_oauth_provider(self, request: State) -> str:
        """ Method to get an OAuth provider from a provided state """

    @abstractmethod
    def get_oauth_provider_access_token(self, request: GetProviderAccessTokenData) -> AccessTokenData:
        """ Method to get the access token of an OAuth provider """

    @abstractmethod
    def record_token_data(self, request: RecordTokenData) -> str | None:
        """ Method to record sensitive token data """

    @abstractmethod
    def get_user_from_uuid(self, request: BaseUser) -> BaseUser | None:
        """ Method to fetch a user from database from its uuid """

    @abstractmethod
    def add_user(self, request: UserWithPassword) -> BaseUser:
        """ Method to add a user into database """

    @abstractmethod
    def get_user_from_credentials(self, request: LoginWithPassword) -> BaseUser | None:
        """ Method to fetch a user from database from its credentials """
