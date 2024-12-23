from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel
from app.crypto.encryption import aes_encrypt_text, aes_decrypt_text, rsa_encrypt_text, rsa_decrypt_text
from app.crypto.file_encryption import aes_encrypt_file, aes_decrypt_file, rsa_encrypt_file, rsa_decrypt_file
from app.key_manager.key_storage import load_keys_from_container
import os

router = APIRouter()

UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def format_aes_key(password: str) -> bytes:
    password_bytes = password.encode()
    return password_bytes.ljust(32, b'0')[:32]


class TextRequest(BaseModel):
    text: str
    algorithm: str
    password: str = None
    key_name: str = None


@router.post("/encrypt-text")
def encrypt_text_endpoint(request: TextRequest):
    try:
        if request.algorithm.lower() == "aes":
            aes_key = format_aes_key(request.password)
            encrypted_text = aes_encrypt_text(request.text, aes_key)
        elif request.algorithm.lower() == "rsa":
            if not request.key_name:
                raise HTTPException(status_code=400, detail="Key name is required for RSA encryption.")
            keys = load_keys_from_container(request.key_name, request.password)

            encrypted_text = rsa_encrypt_text(request.text, keys["public_key"])
        else:
            raise HTTPException(status_code=400, detail="Unsupported encryption algorithm.")

        return {"encrypted_text": encrypted_text}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))




@router.post("/decrypt-text")
def decrypt_text_endpoint(request: TextRequest):
    try:
        if request.algorithm.lower() == "aes":
            aes_key = format_aes_key(request.password)
            decrypted_text = aes_decrypt_text(request.text, aes_key)
        elif request.algorithm.lower() == "rsa":
            if not request.key_name:
                raise HTTPException(status_code=400, detail="Key name is required for RSA decryption.")
            keys = load_keys_from_container(request.key_name, request.password)

            # Передаем private_key как байты
            decrypted_text = rsa_decrypt_text(request.text, keys["private_key"])
        else:
            raise HTTPException(status_code=400, detail="Unsupported decryption algorithm.")

        return {"decrypted_text": decrypted_text}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))




@router.post("/encrypt-file")
async def encrypt_file_endpoint(
    file: UploadFile = File(...),
    algorithm: str = Form(...),
    password: str = Form(None),
    key_name: str = Form(None),
):
    try:
        input_path = os.path.join(UPLOAD_DIR, file.filename)
        output_path = input_path + ".enc"

        with open(input_path, "wb") as f:
            f.write(await file.read())

        if algorithm.lower() == "aes":
            aes_key = format_aes_key(password)
            aes_encrypt_file(input_path, output_path, aes_key)

        elif algorithm.lower() == "rsa":
            if not key_name:
                raise HTTPException(status_code=400, detail="Key name is required for RSA encryption.")
            keys = load_keys_from_container(key_name, password)
            rsa_encrypt_file(input_path, output_path, keys["public_key"])

        else:
            raise HTTPException(status_code=400, detail="Unsupported encryption algorithm.")

        return {"message": "File encrypted successfully", "output_file": output_path}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/decrypt-file")
async def decrypt_file_endpoint(
    file: UploadFile = File(...),
    algorithm: str = Form(...),
    password: str = Form(None),
    key_name: str = Form(None),
):
    try:
        input_path = os.path.join(UPLOAD_DIR, file.filename)
        output_path = input_path + ".dec"

        with open(input_path, "wb") as f:
            f.write(await file.read())

        if algorithm.lower() == "aes":
            aes_key = format_aes_key(password)
            aes_decrypt_file(input_path, output_path, aes_key)

        elif algorithm.lower() == "rsa":
            if not key_name:
                raise HTTPException(status_code=400, detail="Key name is required for RSA decryption.")
            keys = load_keys_from_container(key_name, password)
            rsa_decrypt_file(input_path, output_path, keys["private_key"])

        else:
            raise HTTPException(status_code=400, detail="Unsupported decryption algorithm.")

        return {"message": "File decrypted successfully", "output_file": output_path}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


encryption_router = router
