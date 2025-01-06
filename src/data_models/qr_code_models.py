"""
    Module to define QR Code models
"""

# External libraries
from pydantic import BaseModel


# Simple models (based on BaseModel)
# ==================================

class BaseQRCode(BaseModel):
    """ The most basic QR Code model """

    qr_code: str | None = None


# Composed models
# ===============

pass
