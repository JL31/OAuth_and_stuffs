"""
    Module to define the abstract Login registry
"""

# Standard libraries
from abc import ABC, abstractmethod

# Data models
from src.data_models.user_models import UserWithMFAData
from src.data_models.qr_code_models import BaseQRCode


class MFARegistry(ABC):
    """ MFA abstract registry definition """

    @abstractmethod
    def record_mfa_key(self, request: UserWithMFAData) -> None:
        """ Method to record a MFA key in database """

    @abstractmethod
    def create_mfa_key_qr_code(self, request: BaseQRCode) -> str:
        """ Method to create the QR Code associated to a MFA key """
