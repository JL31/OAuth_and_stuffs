"""
    Module to define OAuth models
"""

# External libraries
from pydantic import BaseModel

# Other data models
from src.data_models.cryptography_models import CryptographicData


# Simple models (based on BaseModel)
# ==================================

class State(BaseModel):
    """ Model to define the OAuth state """

    state: str | None = None


class AuthorizationUrl(BaseModel):
    """ Model to define an OAuth authorization URL """

    authorization_url: str | None = None


class OAuthProvider(BaseModel):
    """ Model to define an OAuth provider """

    oauth_provider: str | None = None


class AccessToken(BaseModel):
    """ Model to define an OAuth provider access token """

    access_token: str | None = None


class AccessTokenDataWithoutAccessToken(BaseModel):
    """ Model to define an OAuth provider access token data without sensitive access token data """

    token_type: str | None = None
    token_scope: list[str] | None = None


class AuthorizationResponse(BaseModel):
    """ Model used to fetch the token access for an OAuth provider """

    authorization_response: str | None = None


class SessionToken(BaseModel):
    """ Model used to get token data """

    session_token: str


# Composed models
# ===============

class GetAuthorizationUrlData(State, AuthorizationUrl):
    """ Model to define data when trying to get authorization URL data """

    pass


class RecordState(State, OAuthProvider):
    """ Model used to record a state for a given OAuth provider """

    pass


class GetProviderAccessTokenData(OAuthProvider, State, AuthorizationResponse):
    """ Model to define data to be used when trying to get an OAuth provider access token data """

    pass


class AccessTokenData(AccessToken, AccessTokenDataWithoutAccessToken):
    """ Model to define an OAuth provider access token data """

    pass


class RecordTokenData(AccessTokenData, OAuthProvider):
    """ Model to define data to be recorded as regards OAuth """

    pass


class AccessTokenDataToRecord(CryptographicData, AccessTokenDataWithoutAccessToken):
    """ Model to define data access token data to record """

    pass


class FetchedAccessTokenData(AccessTokenData, OAuthProvider):
    """ Model used when access token data have been fetched from database """

    pass
