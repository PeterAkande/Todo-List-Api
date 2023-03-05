from pydantic import BaseModel


class SchemasBase(BaseModel):
    class Config:
        orm_mode = True
