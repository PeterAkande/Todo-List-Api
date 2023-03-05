from datetime import datetime, timedelta

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from passlib.context import CryptContext
from typing import Union

from pydantic import ValidationError, EmailStr

from src.app.settings import settings
from src.auth.schemas import User
from src.auth import exceptions

password_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2scheme = OAuth2PasswordBearer(tokenUrl='token')


def hash_password(password: str) -> str:
    """
    :param password: The password to be hashed
    :return: The hashed Password
    """

    return password_context.hash(password)


def verify_hashed_password(plain_password: str, hashed_password: str) -> bool:
    """
    :param plain_password: The password to be checked if it is equal to the hashed password after being hashed
    :param hashed_password: The already hased password, most likely coming from the database
    :return: a bool if the passwords match
    """

    is_equal = password_context.verify(plain_password, hashed_password)

    return is_equal


def create_access_token(user_id: int, expiry_in: Union[int, None] = None) -> str:
    """
    :param expiry_in: This is the nuber of minutes the token would be active for.
    :param user_id: This is the id of the user in the database
    :return: Return the Access token
    """

    if expiry_in is None:
        # The number of minutes was not passed
        # Let the default be 60 minutes(1 hour)
        expiry_in = 60
        pass

    current_date = datetime.now()  # Get the current data
    date_of_expiry = current_date + timedelta(minutes=expiry_in)

    # The data to be encrypted in the user token. More data like the permissions this access token gives,
    # There is a really wide range of choice
    data_to_be_encrypted = {
        'expiry_time': date_of_expiry.isoformat(),
        'user_id': user_id
    }

    # Create the access token
    access_token = jwt.encode(data_to_be_encrypted, settings.JWT_ACCESS_SECRET_KEY,
                              settings.ACCESS_TOKEN_HASH_ALGORITHM)

    return access_token


def create_refresh_token(user_id: int, expiry_in: Union[int, None] = None) -> str:
    """
    :param expiry_in: This is the nuber of minutes the token would be active for.
    :param user_id: This is the id of the user in the database. Would be needed to create another access token
    :return: Return the Refresh token
    """

    if expiry_in is None:
        # The number of minutes was not passed
        # Let the default be 2 days
        expiry_in = 60 * 24 * 2
        pass

    current_date = datetime.now()  # Get the current data
    date_of_expiry = current_date + timedelta(minutes=expiry_in)

    # The data to be encrypted in the user token. More data like the permissions this access token gives,
    # There is a really wide range of choice

    data_to_be_encrypted = {
        'expiry_time': date_of_expiry.isoformat(),
        'user_id': user_id
    }

    # Create the refresh token
    refresh_token = jwt.encode(data_to_be_encrypted, settings.JWT_REFRESH_SECRET_KEY,
                               settings.ACCESS_TOKEN_HASH_ALGORITHM)

    return refresh_token


def get_current_user(access_token: str = Depends(oauth2scheme)) -> User:
    """
    :param access_token: The access token that must have been supplied by the user
    :return: Return the user model if the user exists
    """
    try:
        payload = jwt.decode(access_token, settings.JWT_ACCESS_SECRET_KEY,
                             algorithms=[settings.ACCESS_TOKEN_HASH_ALGORITHM])

        # The token was validated
        # Now get the required data
        expiry_time_str = payload.get('expiry_time', None)
        user_id: int = payload.get('user_id', None)

        if user_id is None or expiry_time_str is None:
            raise exceptions.INVALID_ACCESS_TOKEN

        expiry_time = datetime.fromisoformat(expiry_time_str)

        # Now, the user id and the expiry time are confirmed
        # Get if the expiry time is lesser than the current time
        is_expired = datetime.utcnow() > expiry_time

        if is_expired:
            raise exceptions.EXPIRED_ACCESS_TOKEN

        # Now, the user is not expired
        # Get the data from the database instead
        return User(id=user_id, email=EmailStr('akandepeter@gmail.com'), is_verified=True, username='peter',
                    first_name='Peter', last_name='Akande')
    except jwt.JWTError:
        raise exceptions.INVALID_ACCESS_TOKEN
    except ValidationError:
        raise exceptions.INVALID_ACCESS_TOKEN

    except Exception as e:
        raise exceptions.INVALID_ACCESS_TOKEN
