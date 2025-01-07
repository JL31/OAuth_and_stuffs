"""
    Module to test an OAuth implementation
"""

# Standard libraries
from os import path, environ, getenv

# External libraries
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from uvicorn import run
from slowapi.errors import RateLimitExceeded

# Loading environment variables
local_environment_variables_path: str = path.join(
    path.dirname(__file__),
    "env_vars",
    ".env.local"
)
load_dotenv(local_environment_variables_path)

# External libraries (bis) : this import SHALL be done after loading environment variables as some are used in the
# router to initialize database connection
from src.endpoints.rest_api_endpoints import router

# FastAPI application
application = FastAPI()
application.include_router(router=router, prefix=getenv("API_PREFIX", ""))

# Exception to prevent bruteforce attacks
@application.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, error: RateLimitExceeded):
    raise HTTPException(
        status_code=429,
        detail="Too many attemps, try later"
    )


# With OAuth it is MANDATORY to use HTTPS
# To test locally it is possible to bypass this behavior through the use of the following command
# NEVER DO SO IN A PRODUCTION ENVIRONMENT !!
print()
print("-")
print("-")
print("Insecure but only for local tests :")
environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
print("OAUTHLIB_INSECURE_TRANSPORT environment variable value : ", environ.get("OAUTHLIB_INSECURE_TRANSPORT"))
print("-")
print("-")
print()

allowed_origins: list[str] = [
    getenv("FRONTEND_URL")  # frontend URL
]

# To avoid CORS issues
application.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,  # Mandatory if cookies are used
    allow_methods=["*"],
    allow_headers=["*"]
)


if __name__ == "__main__":
    run(
        app="main:application",
        host=getenv("LOCAL_SERVER_HOST"),
        port=int(getenv("LOCAL_SERVER_PORT", 0)),
        ssl_keyfile=f'{getenv("SSL_FILES_LOCATION")}/{getenv("SSL_KEYFILE")}',
        ssl_certfile=f'{getenv("SSL_FILES_LOCATION")}/{getenv("SSL_CERTFILE")}'
    )
