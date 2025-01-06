"""
    Module to define the MFA check usecase
"""

# Tools
from src.tools.abstractions.abstract_usecase import AbstractUsecase
from src.tools.mfa_and_totp.totp_handling import calculate_totp

# Registries
from src.registries.login_registry import LoginRegistry

# Data models
from src.data_models.user_models import UserWithTOTPTokenData, UserWithMFAData

# Exceptions
from src.exceptions.resource_not_found_exception import ResourceNotFoundException
from src.exceptions.invalid_credentials_exception import InvalidCredentialsException


class MFACheckUsecase(AbstractUsecase):
    """ MFA check usecase implementation """

    def __init__(self, login_registry: LoginRegistry):
        """ MFA creation usecase constructor """

        self.login_registry: LoginRegistry = login_registry

    def execute(self, usecase_request: UserWithTOTPTokenData) -> None:
        """ Method to check a MFA """

        fetched_mfa_data: UserWithMFAData | None = self.login_registry.get_user_from_uuid_with_mfa_data(usecase_request)
        if not fetched_mfa_data:
            raise ResourceNotFoundException(f"No user found with uuid : '{usecase_request.user_uuid}'")

        if not fetched_mfa_data.mfa_key:
            raise ValueError(f"No MFA key available for user with uuid : '{usecase_request.user_uuid}'")

        if usecase_request.totp_token != calculate_totp(fetched_mfa_data.mfa_key):
            raise InvalidCredentialsException("Invalid TOTP token")

        return None
