"""
    Module to define the login usecase
"""

# Tools
from src.tools.abstractions.abstract_usecase import AbstractUsecase

# Registries
from src.registries.login_registry import LoginRegistry

# Data models
from src.data_models.login_models import LoginWithPassword
from src.data_models.user_models import BaseUser

# Exceptions
from src.exceptions.invalid_credentials_exception import InvalidCredentialsException


class LoginUsecase(AbstractUsecase):
    """ Login usecase implementation """

    def __init__(self, login_registry: LoginRegistry):
        """ Login usecase constructor """

        self.login_registry: LoginRegistry = login_registry

    def execute(self, usecase_request: LoginWithPassword) -> BaseUser:
        """ Method to perform login """

        fetched_user: BaseUser | None = self.login_registry.get_user_from_credentials(usecase_request)
        if not fetched_user:
            raise InvalidCredentialsException(f"Invalid credentials")

        return fetched_user
