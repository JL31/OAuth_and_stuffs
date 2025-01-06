"""
    Module to define login models
"""

# External libraries
from pydantic import BaseModel, EmailStr, HttpUrl

# Other data models
from src.data_models.oauth_models import State


# Simple models (based on BaseModel)
# ==================================

class Login(BaseModel):
    """ The most basic login model """

    login_email: EmailStr | None = None


class URL(BaseModel):
    """ The most basic URL model """

    url: HttpUrl | None = None


# Composed models
# ===============

class LoginWithPassword(Login):
    """ Login model with plain text password """

    password: str | None = None


class LoginWithHashedPassword(Login):
    """ Login model with hashed password """

    hashed_password: str | None = None


class CallbackLogin(State, URL):
    """ Model used with callback login """

    pass
