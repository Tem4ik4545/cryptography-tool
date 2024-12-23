from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from app.key_manager.key_storage import save_private_key_to_container
import os

def generate_symmetric_key(length: int = 32) -> bytes:
    """
    Генерация симметричного ключа для AES.
    :param length: Длина ключа в байтах (по умолчанию 32 байта = 256 бит).
    :return: Байтовый ключ.
    """
    return os.urandom(length)

def generate_rsa_key_pair(key_name: str, password: str):
    """
    Генерация пары RSA-ключей.
    Приватный ключ сохраняется в контейнере, публичный - в корневой папке.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Сохраняем публичный ключ в файл
    public_key_path = f"public_key_{key_name}.pem"
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    # Сохраняем приватный ключ в контейнер
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    save_private_key_to_container(key_name, password, private_key_pem)