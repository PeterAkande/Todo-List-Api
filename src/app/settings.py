import os.path

from pydantic import BaseSettings
from starlette.staticfiles import PathLike


class Settings(BaseSettings):
    """
    This would handle the whole settings for the application
    """
    JWT_ACCESS_SECRET_KEY: str
    JWT_REFRESH_SECRET_KEY: str
    ACCESS_TOKEN_HASH_ALGORITHM: str

    class Config:
        env_file = os.path.join(os.getcwd(), '.env')


settings = Settings()
