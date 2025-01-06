"""
    Module to define User models
"""

# External libraries
from pydantic import BaseModel, EmailStr

# Other data models
from src.data_models.mfa_models import BaseMFA, TOTPToken


# Simple models (based on BaseModel)
# ==================================

class BaseUser(BaseModel):
    """ The most basic user model """

    user_uuid: str | None = None
    user_email: EmailStr | None = None


# Composed models
# ===============

class UserWithPassword(BaseUser):
    """ User model with plain text password """

    user_password: str | None = None


class UserWithHashedPassword(BaseUser):
    """ User model with hashed password """

    user_hashed_password: str | None = None


class UserWithMFAData(BaseUser, BaseMFA):
    """ User model enriched with MFA data """


class UserWithTOTPTokenData(BaseUser, TOTPToken):
    """ User model enriched with TOTP Token data """
