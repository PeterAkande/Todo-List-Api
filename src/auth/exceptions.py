from fastapi import HTTPException
from fastapi import status

# This is an exception when pydantic couldn't validate the given data.
INVALID_ACCESS_TOKEN = HTTPException(
    detail='Invalid Access Token',
    status_code=400,
)

# When the refresh token is expired
EXPIRED_REFRESH_TOKEN = HTTPException(
    detail='Token Has Expired. Please Login again to get a new Token',
    status_code=401
)

# When the access token is expired
EXPIRED_ACCESS_TOKEN = HTTPException(
    detail='Token Has Expired. Please update access token using the fresh token',
    status_code=401
)

INCORRECT_SIGN_IN_CREDENTIALS = HTTPException(
    detail='Account not found, Email or Password not correct',
    status_code=404
)

EMAIL_EXISTS_ERROR = HTTPException(
    detail='Email Exists',
    status_code=status.HTTP_406_NOT_ACCEPTABLE
)

USERNAME_EXISTS_ERROR = HTTPException(
    detail='Username Exists',
    status_code=status.HTTP_406_NOT_ACCEPTABLE
)
