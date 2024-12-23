from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fastapi import APIRouter, HTTPException
import datetime
from cryptography.x509 import load_pem_x509_certificate
from pydantic import BaseModel
from app.crypto.signature import  calculate_file_hash, sign_file, verify_file_signature
from cryptography.x509.oid import NameOID
from app.key_manager.key_generation import generate_rsa_key_pair
from app.key_manager.key_storage import load_keys_from_container, delete_key_from_container
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key
)
import os


router = APIRouter()
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)


class GenerateKeysRequest(BaseModel):
    key_name: str
    password: str


@router.post("/generate-keys")
def generate_keys(request: GenerateKeysRequest):
    """
    Генерация RSA-ключей. Публичный ключ сохраняется в файл,
    а приватный - в зашифрованный контейнер.
    """
    try:
        generate_rsa_key_pair(request.key_name, request.password)
        return {"message": "Keys generated successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/remove-key")
def remove_key_endpoint(key_name: str, password: str):
    try:
        # Удаление приватного ключа из контейнера
        delete_key_from_container(key_name, password)

        # Путь к публичному ключу
        public_key_path = f"public_key_{key_name}.pem"

        # Проверяем и удаляем публичный ключ
        if os.path.exists(public_key_path):
            os.remove(public_key_path)

        return {"message": f"Key '{key_name}' deleted successfully."}
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Key '{key_name}' not found.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/hash-file")
async def hash_file_endpoint(file: UploadFile = File(...)):
    try:
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as f:
            f.write(await file.read())

        file_hash = calculate_file_hash(file_path)
        return {"file_hash": file_hash}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/sign-file")
async def sign_file_endpoint(
    file: UploadFile = File(...),
    key_name: str = Form(...),
    password: str = Form(...)
):
    try:
        # Сохранение загруженного файла
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as f:
            f.write(await file.read())

        # Вычисление хэшсуммы файла
        file_hash = calculate_file_hash(file_path)

        # Загрузка ключей из контейнера
        keys = load_keys_from_container(key_name, password)

        # Генерация подписи
        signature = sign_file(file_path, keys["private_key"])

        # Сохранение подписи
        signature_path = file_path + ".sig"
        with open(signature_path, "wb") as f:
            f.write(signature)

        # Создание X.509-сертификата
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"User Certificate"),
        ])
        issuer = subject  # Самоподписанный сертификат
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            load_pem_public_key(keys["public_key"], backend=default_backend())
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(
            load_pem_private_key(keys["private_key"], password=None, backend=default_backend()),
            hashes.SHA256()
        )

        # Сохранение сертификата
        certificate_path = file_path + ".cert"
        with open(certificate_path, "wb") as f:
            f.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))

        return {
            "message": "File signed successfully",
            "signature_file": signature_path,
            "certificate_file": certificate_path,
            "file_hash": file_hash  # Добавлено
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/verify-file")
async def verify_file_endpoint(
    file: UploadFile = File(...),
    signature: UploadFile = File(...),
    certificate: UploadFile = File(...)
):
    try:
        # Сохранение файлов
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as f:
            f.write(await file.read())

        signature_path = os.path.join(UPLOAD_DIR, signature.filename)
        with open(signature_path, "wb") as f:
            f.write(await signature.read())

        certificate_path = os.path.join(UPLOAD_DIR, certificate.filename)
        with open(certificate_path, "wb") as f:
            f.write(await certificate.read())

        # Чтение содержимого подписи и сертификата
        with open(signature_path, "rb") as f:
            signature_data = f.read()

        with open(certificate_path, "rb") as f:
            certificate_data = f.read()

        # Проверка подписи
        is_valid = verify_file_signature(file_path, signature_data, certificate_data)

        if is_valid:
            return {"message": "Signature is valid."}
        else:
            return {"message": "Signature is invalid."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))



# Роутер
signature_router = router
