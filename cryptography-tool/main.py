from fastapi import FastAPI
from app.api.encryption_api import encryption_router
from app.api.signature_api import signature_router

app = FastAPI(title="Cryptography Tool API", version="1.0")

# Подключение маршрутов
app.include_router(encryption_router, prefix="/encryption", tags=["Encryption"])
app.include_router(signature_router, prefix="/signature", tags=["Signature"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the Cryptography Tool API"}
