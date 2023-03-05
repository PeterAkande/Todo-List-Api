from fastapi import FastAPI

from src.auth.route import auth_router

app = FastAPI()
app.include_router(auth_router)


@app.get('/', tags=['Home'])
def home():
    return {"Hello": "World"}
