"""
    Module to define the REST API endpoints
"""

# Standard libraries
from logging import Logger
from os import getenv

# Externals libraries
from fastapi import APIRouter, Request, HTTPException, status, Depends, Cookie
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from redis import Redis
from jwt import ExpiredSignatureError, PyJWTError
from slowapi import Limiter
from slowapi.util import get_remote_address

# Usecases
from src.usecases.oauth_login.oauth_login_usecase import OAuthLoginUsecase
from src.usecases.login.login_usecase import LoginUsecase
from src.usecases.callback_login.callback_login_usecase import CallbackLoginUsecase
from src.usecases.subscription.subscription_usecase import SubscriptionUsecase
from src.usecases.mfa_creation.mfa_creation_usecase import MFACreationUsecase
from src.usecases.mfa_check.mfa_check_usecase import MFACheckUsecase

# Data models
from src.data_models.login_models import LoginWithPassword, CallbackLogin
from src.data_models.oauth_models import OAuthProvider, AuthorizationUrl, SessionToken, FetchedAccessTokenData
from src.data_models.user_models import BaseUser, UserWithMFAData, UserWithTOTPTokenData

# Registries implementations
from src.registries_implementations.login_registry_implementation import LoginRegistryImplementation
from src.registries_implementations.mfa_registry_implementation import MFARegistryImplementation

# Tools
from src.tools.redis.redis_connector import redis_connector
from src.tools.postgresql.postgresql_connector import postgresql_connector
from src.tools.logger.get_logger import get_logger
from src.tools.jwt.jwt_handling import encode_session_token, decode_session_token

# Exceptions
from src.exceptions.invalid_parameter_exception import InvalidParameterException
from src.exceptions.invalid_credentials_exception import InvalidCredentialsException
from src.exceptions.resource_not_found_exception import ResourceNotFoundException

# Configuration
router = APIRouter()

# Databases connectors
redis_connector: Redis = redis_connector()
postgresql_connector = postgresql_connector(statement_timeout_value=30000)  # the statement timeout value is expressed in milliseconds

# Global variables
ENCODING: str = "utf-8"
LOGGER: Logger = get_logger("REST_API_ENDPOINTS")
BRUTEFORCE_LIMITATION: str = "3/minute"  # 3 calls per minute allowed

# Registries implementations
login_registry = LoginRegistryImplementation(redis_client=redis_connector, database_connector=postgresql_connector)
mfa_registry = MFARegistryImplementation(database_connector=postgresql_connector)

# Usecases
oauth_login_usecase = OAuthLoginUsecase(login_registry)
login_usecase = LoginUsecase(login_registry)
callback_login_usecase = CallbackLoginUsecase(login_registry)
subscription_usecase = SubscriptionUsecase(login_registry)
mfa_creation_usecase = MFACreationUsecase(login_registry, mfa_registry)
mfa_check_usecase = MFACheckUsecase(login_registry)

# Limiter configuration (to prevent bruteforce attacks)
limiter = Limiter(key_func=get_remote_address)

def get_limiter() -> Limiter:
    """ Function to return API limiter to protect against bruteforce attacks """

    return limiter


def create_response_with_jwt(data: dict, redirection: bool = True) -> RedirectResponse | JSONResponse:
    """ Function to create an HTTP response including a JWT """

    jwt_token: str = encode_session_token(provided_data=data)

    response: RedirectResponse | JSONResponse

    if redirection:
        redirection_url: str = f'{getenv("FRONTEND_URL")}{getenv("FRONTEND_REDIRECTION_URL")}'
        response = RedirectResponse(url=redirection_url)

    else:
        response = JSONResponse(
            status_code=200,
            content={
                "code": status.HTTP_200_OK,
                "message": "Successful"
            }
    )

    response.set_cookie(
        key="session_token",
        value=jwt_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=int(getenv("ACCESS_TOKEN_EXPIRATION_IN_MINUTES")) * 60
        # domain="localhost"  # TODO : à tester, cf https://grafikart.fr/tutoriels/cors-http-navigateur-1180
    )

    return response


def get_decoded_session_token(session_token: str = Cookie(...)) -> dict:
    """ Function to decode a session token """

    try:
        decoded_session_token: dict | None = decode_session_token(session_token)
        if not decode_session_token:
            raise HTTPException(status_code=401, detail="Invalid token")

        return decoded_session_token

    except ExpiredSignatureError as error:
        LOGGER.error("get_decoded_session_token - ExpiredSignatureError")
        LOGGER.exception(error)
        raise HTTPException(status_code=401, detail="Token expired")

    except PyJWTError as error:
        LOGGER.error("get_decoded_session_token - PyJWTError")
        LOGGER.exception(error)
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_token_uuid(decoded_session_token: dict = Depends(get_decoded_session_token)) -> FetchedAccessTokenData | dict | HTTPException:
    """
    Function to extract token uuid from session token.
    If no data could be found it returns the decoded session token
    """

    token_uuid: str | None = decoded_session_token.get("token_uuid")
    if not token_uuid:
        return decoded_session_token

    try:
        fetched_oauth_token: FetchedAccessTokenData | None = login_registry.get_oauth_token(
            SessionToken(session_token=token_uuid)
        )
        return fetched_oauth_token

    except Exception as error:
        LOGGER.error("get_current_token_uuid")
        LOGGER.exception(error)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error")


def get_current_token_or_user_uuid(token_data: FetchedAccessTokenData | dict = Depends(get_current_token_uuid)) -> FetchedAccessTokenData | BaseUser | HTTPException:
    """ Function to get current token uuid or user uuid depending on the login process """

    if isinstance(token_data, FetchedAccessTokenData) and token_data.access_token:
        return token_data

    try:
        fetched_user: BaseUser | None = login_registry.get_user_from_uuid(BaseUser(user_uuid=token_data.get("user_uuid")))
        if not fetched_user:
            raise HTTPException(status_code=401, detail="Invalid token")

        return fetched_user

    except Exception as error:
        LOGGER.error("get_current_token_or_user_uuid")
        LOGGER.exception(error)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unexpected error")


@router.get(path="/oauth_login/{provider}")
def oauth_login(request: Request):
    """ Route to handle login through OAuth """

    path_parameters: dict = dict(request.path_params)
    oauth_provider: str | None = path_parameters.get("provider")

    try:
        provider = OAuthProvider(oauth_provider=oauth_provider)
        usecase_response: AuthorizationUrl = oauth_login_usecase.execute(provider)
        return RedirectResponse(usecase_response.authorization_url)

    except InvalidParameterException as error:
        LOGGER.error("oauth_login - InvalidParameterException")
        LOGGER.exception(error)
        raise HTTPException(status_code=400, detail="Invalid parameter")
        # TODO : alternative :
        #         return JSONResponse(
        #             status_code=400,
        #             content={
        #                 "code": status.HTTP_400_BAD_REQUEST,
        #                 "message": "Invalid parameter"
        #             }
        #         )
        #       >>> envisager également de créer des exceptions plus génériques (si possible avec le même genre de
        #           réponse qu'en cas de return JSONResponse, i.e. avec un content qui détaille le code et un message (à
        #           mettre dans detail ?)

    except Exception as error:
        LOGGER.error("oauth_login - Exception")
        LOGGER.exception(error)
        raise HTTPException(status_code=500, detail="Unexpected error")


@router.post(path="/subscription")
def subscription(form_data: OAuth2PasswordRequestForm = Depends()):
    """ Route to handle subscription with email (username) and password """

    # TODO : pas urgent mais prendre des infos sur le grant-type :
    #        - A quoi ça sert ?
    #        - Est-ce qu'il faut que je l'utilise aussi ?

    try:
        request = LoginWithPassword(login_email=form_data.username, password=form_data.password)
        added_user: BaseUser = subscription_usecase.execute(request)
        return create_response_with_jwt(
            data={
                "user_uuid": added_user.user_uuid,
                "has_mfa": False
            },
            redirection=False
        )

    except InvalidParameterException as error:
        LOGGER.error("subscription - InvalidParameterException")
        LOGGER.exception(error)
        raise HTTPException(status_code=400, detail="Invalid parameter")

    except Exception as error:
        LOGGER.error("subscription - Exception")
        LOGGER.exception(error)
        raise HTTPException(status_code=500, detail="Unexpected error")


@router.post(path="/login")
@get_limiter().limit(BRUTEFORCE_LIMITATION)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):  # request is mandatory for bruteforce prevention
    """ Route to handle login with email (username) and password """

    try:
        request = LoginWithPassword(login_email=form_data.username, password=form_data.password)
        usecase_response: UserWithMFAData = login_usecase.execute(request)
        user_with_mfa: bool = True if usecase_response.mfa_uuid else False

        if user_with_mfa:  # credentials are OK but to properly log in user must input MFA
            return JSONResponse(
                status_code=202,
                content={
                    "code": status.HTTP_202_ACCEPTED,
                    "message": "Successful login, MFA check required",
                    "user_uuid": usecase_response.user_uuid
                }
            )

        else: # credentials are OK and since there is no MFA no need to process further so JWT is sent
            return create_response_with_jwt(
                data={
                    "user_uuid": usecase_response.user_uuid,
                    "has_mfa": user_with_mfa
                },
                redirection=False
            )

    except InvalidCredentialsException as error:
        LOGGER.error("login - InvalidCredentialsException")
        LOGGER.exception(error)
        raise HTTPException(status_code=400, detail="Invalid parameter")

    except Exception as error:
        LOGGER.error("login - Exception")
        LOGGER.exception(error)
        raise HTTPException(status_code=500, detail="Unexpected error")


@router.get(path="/auth/callback")
def callback(request: Request):
    """ Callback route to get authorization token """

    query_parameters: dict = dict(request.query_params)
    state: str | None = query_parameters.get("state")
    if not state:
        return JSONResponse("No provided state, impossible to log user")
    request_url: str = str(request.url)

    try:
        request = CallbackLogin(
            state=state,
            url=request_url
        )
        token_uuid: str = callback_login_usecase.execute(request)

        return create_response_with_jwt(data={"token_uuid": token_uuid})

    except InvalidParameterException as error:
        LOGGER.error("callback - InvalidParameterException")
        LOGGER.exception(error)
        raise HTTPException(status_code=400, detail="Invalid parameter")

    except Exception as error:
        LOGGER.error("callback - Exception")
        LOGGER.exception(error)
        raise HTTPException(status_code=500, detail="Unexpected error")


@router.post(path="/mfa/create")
def mfa_creation(current_token_or_user_uuid: FetchedAccessTokenData | BaseUser = Depends(get_current_token_or_user_uuid)):
    """ Route to create a MFA for a given user """

    if not isinstance(current_token_or_user_uuid, BaseUser):
        raise HTTPException(status_code=400, detail="MFA creation is only valid for registered users")

    try:
        request = BaseUser(user_uuid=current_token_or_user_uuid.user_uuid)
        mfa_key_qr_code: str = mfa_creation_usecase.execute(request)
        return JSONResponse(
            status_code=201,
            content={
                "code": status.HTTP_201_CREATED,
                "data": {
                    "MFAKeyQrCode": mfa_key_qr_code
                }
            }
        )

    except InvalidCredentialsException as error:
        LOGGER.error("mfa_creation - InvalidCredentialsException")
        LOGGER.exception(error)
        raise HTTPException(status_code=400, detail="Invalid parameter")

    except ResourceNotFoundException as error:
        LOGGER.error("mfa_creation - ResourceNotFoundException")
        LOGGER.exception(error)
        raise HTTPException(status_code=400, detail="Invalid parameter")

    except Exception as error:
        LOGGER.error("mfa_creation - Exception")
        LOGGER.exception(error)
        raise HTTPException(status_code=500, detail="Unexpected error")


@router.post(path="/mfa/check")
def mfa_check(mfa_check_data: UserWithTOTPTokenData):
    """ Route to check a MFA for a given user """

    try:
        request = UserWithTOTPTokenData(
            totp_token=mfa_check_data.totp_token,
            user_uuid=mfa_check_data.user_uuid
        )
        mfa_check_usecase.execute(request)
        return create_response_with_jwt(
            data={
                "user_uuid": mfa_check_data.user_uuid,
                "has_mfa": True
            },
            redirection=False
        )

    except InvalidCredentialsException as error:
        LOGGER.error("mfa_check - InvalidCredentialsException")
        LOGGER.exception(error)
        raise HTTPException(status_code=400, detail="Invalid parameter")

    except ResourceNotFoundException as error:
        LOGGER.error("mfa_check - ResourceNotFoundException")
        LOGGER.exception(error)
        raise HTTPException(status_code=400, detail="Invalid parameter")

    except Exception as error:
        LOGGER.error("mfa_check - Exception")
        LOGGER.exception(error)
        raise HTTPException(status_code=500, detail="Unexpected error")


# TODO : implémenter l'anti-bruteforce
# TODO : gérer la connexion automatique dans les APIs de login
