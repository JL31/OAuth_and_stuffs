"""
    Module to define MFA models
"""

# External libraries
from pydantic import BaseModel


# Simple models (based on BaseModel)
# ==================================

class BaseMFA(BaseModel):
    """ The most basic MFA model """

    mfa_uuid: str | None = None
    mfa_key: str | None = None


class TOTPToken(BaseModel):
    """ The most basic TOTP Token model """

    totp_token: str | None = None


# Composed models
# ===============
