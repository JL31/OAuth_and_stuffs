"""
    Module to define the MFA creation usecase
"""

# Tools
from src.tools.abstractions.abstract_usecase import AbstractUsecase
from src.tools.mfa_and_totp.mfa_key_handling import generate_new_mfa_key

# Registries
from src.registries.login_registry import LoginRegistry
from src.registries.mfa_registry import MFARegistry

# Data models
from src.data_models.user_models import BaseUser, UserWithMFAData
from src.data_models.qr_code_models import BaseQRCode

# Exceptions
from src.exceptions.resource_not_found_exception import ResourceNotFoundException


class MFACreationUsecase(AbstractUsecase):
    """ MFA creation usecase implementation """

    def __init__(self, login_registry: LoginRegistry, mfa_registry: MFARegistry):
        """ MFA creation usecase constructor """

        self.login_registry: LoginRegistry = login_registry
        self.mfa_registry: MFARegistry = mfa_registry

    def execute(self, usecase_request: BaseUser) -> str:
        """ Method to create a MFA """

        fetched_mfa_data: UserWithMFAData | None = self.login_registry.get_user_from_uuid_with_mfa_data(usecase_request)
        if not fetched_mfa_data:
            raise ResourceNotFoundException(f"No user found with uuid : '{usecase_request.user_uuid}'")

        if fetched_mfa_data.mfa_key:
            raise ValueError(f"A MFA key has already been created for user with uuid : '{usecase_request.user_uuid}'")

        mfa_key: str = generate_new_mfa_key()

        self.mfa_registry.record_mfa_key(
            UserWithMFAData(
                mfa_key=mfa_key,
                user_uuid=fetched_mfa_data.user_uuid
            )
        )

        google_authenticator_qr_code: str = "&".join(
            [
                "otpauth://totp/{issuer}:{email}?secret={secret}",
                "issuer={issuer}"
            ]
        ).format(
            issuer="JL31",
            email=fetched_mfa_data.user_email,
            secret=mfa_key,
        )
        mfa_key_qr_code: str = self.mfa_registry.create_mfa_key_qr_code(
            BaseQRCode(qr_code=google_authenticator_qr_code)
        )
        if not mfa_key_qr_code:
            raise ValueError()

        return mfa_key_qr_code
