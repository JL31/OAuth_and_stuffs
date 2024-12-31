"""
    Module to define the subscription usecase implementation
"""

# Tools
from src.tools.abstractions.abstract_usecase import AbstractUsecase

# Registries
from src.registries.login_registry import LoginRegistry

# Data models
from src.data_models.login_models import LoginWithPassword
from src.data_models.user_models import BaseUser, UserWithPassword

# Exceptions
from src.exceptions.registry_exception import RegistryException


class SubscriptionUsecase(AbstractUsecase):
    """ Subscription usecase implementation """

    def __init__(self, login_registry: LoginRegistry) -> None:
        """ Subscription usecase class constructor """

        self.login_registry: LoginRegistry = login_registry

    def execute(self, usecase_request: LoginWithPassword) -> BaseUser:
        """ Performs a user subscription """

        added_user: BaseUser | None = self.login_registry.add_user(
            UserWithPassword(email=usecase_request.email, password=usecase_request.password)
        )
        if not added_user:
            raise RegistryException(f"Issue when trying to add user data with email : '{usecase_request.email}'")

        if added_user.email != usecase_request.email:
            error_message: str  = "\n".join(
                [
                    "Provided email (from request) does not match email recorded into database : ",
                    f"- provided email (from request) : {usecase_request.email}",
                    f"- recorded email : {added_user.email}"
                ]
            )
            raise RegistryException(error_message)

        return added_user
