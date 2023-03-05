from pydantic import BaseModel, EmailStr

from src.app.utils.schema_utils import SchemasBase


class UserBase(BaseModel):
    """
      This is the base model for the user model
      """
    username: str
    email: EmailStr
    first_name: str
    last_name: str


class User(UserBase):
    id: int
    is_verified: bool


class UserSignInRequest(BaseModel):
    """
    Might not be needed though, can use OAuth2PasswordRequestForm
    """
    email: EmailStr
    password: str


class UserSignUpRequest(UserBase):
    password: str


class UserInDb(User, SchemasBase):
    """
    The User Base Model in the Database
    """
    hashed_password: str


class Token(BaseModel):
    """
    This is the Token Model, and it would hold the token access id
    It would be found in the header of the request
    """
    access_token: str
    refresh_token: str


class UserDetailsResponse(UserBase):
    """
    Response When a user Signs in
    """
    is_verified: bool


class UserSignUpOrSignUpResponse(UserDetailsResponse):
    """
    This is the response when the user account has been created
    """
    token: Token
