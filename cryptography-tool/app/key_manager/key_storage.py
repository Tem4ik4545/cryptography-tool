import json
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

CONTAINER_FILE = "key_container.aes"

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Генерация ключа на основе пароля и соли.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def format_aes_key(password: str) -> bytes:
    """
    Преобразует пароль в ключ длиной 32 байта для AES.
    """
    password_bytes = password.encode('utf-8')
    return password_bytes.ljust(32, b'0')[:32]

def save_private_key_to_container(key_name: str, password: str, private_key: bytes):

    salt = os.urandom(16)
    aes_key = derive_key(password, salt)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(private_key) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    container_entry = {key_name: {"salt": salt.hex(), "iv": iv.hex(), "data": encrypted_data.hex()}}

    if os.path.exists(CONTAINER_FILE):
        with open(CONTAINER_FILE, "r") as f:
            container = json.load(f)
    else:
        container = {}

    container.update(container_entry)

    with open(CONTAINER_FILE, "w") as f:
        json.dump(container, f)

def load_keys_from_container(key_name: str, password: str) -> dict:
    if not os.path.exists(CONTAINER_FILE):
        raise FileNotFoundError("Key container not found.")

    with open(CONTAINER_FILE, "r") as f:
        container = json.load(f)

    if key_name not in container:
        raise KeyError(f"Key '{key_name}' not found in container.")

    salt = bytes.fromhex(container[key_name]["salt"])
    iv = bytes.fromhex(container[key_name]["iv"])
    encrypted_data = bytes.fromhex(container[key_name]["data"])
    aes_key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    private_key = unpadder.update(padded_data) + unpadder.finalize()

    public_key_path = f"public_key_{key_name}.pem"
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key file '{public_key_path}' not found.")

    with open(public_key_path, "rb") as f:
        public_key = f.read()

    return {"private_key": private_key, "public_key": public_key}



def delete_key_from_container(key_name: str, password: str):
    """
    Удаляет ключ из контейнера.
    """
    if not os.path.exists(CONTAINER_FILE):
        raise FileNotFoundError("Key container not found.")

    with open(CONTAINER_FILE, "r") as f:
        container = json.load(f)

    if key_name not in container:
        raise KeyError(f"Key '{key_name}' not found in container.")

    # Удаляем ключ
    del container[key_name]

    # Сохраняем обновлённый контейнер
    with open(CONTAINER_FILE, "w") as f:
        json.dump(container, f)
