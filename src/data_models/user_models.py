"""
    Module to define User models
"""

# External libraries
from pydantic import BaseModel, EmailStr


# Simple models (based on BaseModel)
# ==================================

class BaseUser(BaseModel):
    """ The most basic user model """

    uuid: str | None = None
    email: EmailStr | None = None


# Composed models
# ===============

class UserWithPassword(BaseUser):
    """ User model with plain text password """

    password: str | None = None


class UserWithHashedPassword(BaseUser):
    """ User model with hashed password """

    hashed_password: str | None = None
