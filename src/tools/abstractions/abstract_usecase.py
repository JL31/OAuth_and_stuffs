"""
    Module to define an abstract usecase
"""

# Standard libraries
from abc import ABC, abstractmethod

# Entities
from src.tools.entities.usecase_abstract_request import UsecaseAbstractRequest
from src.tools.entities.usecase_abstract_response import UsecaseAbstractResponse

# External libraries
from pydantic import BaseModel


class AbstractUsecase(ABC):
    """ Abstrcat usecase definition """

    @abstractmethod
    def execute(self, usecase_request: UsecaseAbstractRequest | BaseModel) -> UsecaseAbstractResponse | BaseModel | None:
        """ Method to perform usecase logic """
