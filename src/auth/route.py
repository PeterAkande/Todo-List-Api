import random

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from src.auth.schemas import UserSignUpRequest, UserSignUpOrSignUpResponse, Token, UserDetailsResponse, User
from src.auth.oauth import create_access_token, create_refresh_token, hash_password, verify_hashed_password, \
    get_current_user
from src.auth import exceptions

auth_router = APIRouter(prefix='/auth', tags=['User Auth'])

users = {}


@auth_router.post('/signup', tags=['User Auth'])
def sign_up(user_details: UserSignUpRequest) -> UserSignUpOrSignUpResponse:
    user_id = random.randint(0, 3)

    refresh_token = create_refresh_token(user_id)
    access_token = create_access_token(user_id)
    token: Token = Token(refresh_token=refresh_token, access_token=access_token)

    hashed_password = hash_password(user_details.password)
    # Now Store the user details in the db

    user = UserSignUpOrSignUpResponse(username=user_details.username, email=user_details.email,
                                      first_name=user_details.email,
                                      last_name=user_details.last_name, is_verified=False, token=token)

    # Some Virtual Db Sha
    user_db_details = {
        'id': user_id,
        'user': user,
        'password': hashed_password
    }

    users[user_details.username] = user_db_details

    return user


@auth_router.post('/signin', tags=['User Auth'])
def sign_in(form_data: OAuth2PasswordRequestForm = Depends()) -> UserSignUpOrSignUpResponse:
    user_db_detail = users.get(form_data.username, None)

    if user_db_detail is None:
        raise exceptions.INCORRECT_SIGN_IN_CREDENTIALS

    # The email has been gotten

    is_password_valid = verify_hashed_password(form_data.password, user_db_detail['password'])

    if not is_password_valid:
        raise exceptions.INCORRECT_SIGN_IN_CREDENTIALS

    # Email and password is confirmed

    return user_db_detail['user']


@auth_router.get('/me', tags=['User Auth'])
def get_my_details(user: User = Depends(get_current_user)) -> UserDetailsResponse:
    return UserDetailsResponse(**user.dict())
